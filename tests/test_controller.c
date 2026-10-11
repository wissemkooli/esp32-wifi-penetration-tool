/* Exercise the actual producer using a deferred task and injected SDK failures. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../main/controller.c"

static attack_job_t current = {.id=7};
static TaskFunction_t pending_task;
static bool fail_task, fail_channel, fail_promisc;
static bool wifi_started = true, phone_connected = true, mismatch;
static wifi_mode_t wifi_mode = WIFI_MODE_APSTA;
static unsigned stop_calls, start_calls, mode_calls;
static esp_err_t stop_error, start_error, mode_error, restore_error;
static unsigned channel_calls, tx_calls, sent, failures, post_retries, deleted;
static char observed_stage[16];
static esp_err_t observed_error;
static esp_wifi_80211_tx_done_cb_t tx_callback;
static esp_err_t register_error;
static bool omit_callbacks;
void attack_controller_diagnostics(uint32_t id, uint32_t ok, uint32_t failed, bool registered, esp_err_t error) {
    assert(id==current.id);
    current.tx_done_ok=ok; current.tx_done_fail=failed;
    current.tx_callback_registered=registered; current.tx_callback_error=error;
}
esp_err_t esp_wifi_register_80211_tx_cb(esp_wifi_80211_tx_done_cb_t cb) {
    if (cb && register_error) return register_error;
    tx_callback=cb; return ESP_OK;
}
void attack_lock(void) {}
void attack_unlock(void) {}
const attack_job_t *attack_get_job(void) { return &current; }
void attack_note_tx(bool ok, unsigned target) { assert(ok && target==0); ++sent; }
esp_err_t attack_controller_failure_request(uint32_t id, esp_err_t err, const char *stage, unsigned target) {
    assert(id==current.id && target==0 && err!=ESP_OK);
    observed_error=err; snprintf(observed_stage,sizeof(observed_stage),"%s",stage);
    ++failures;
    if (post_retries) { --post_retries; return ESP_ERR_TIMEOUT; }
    return ESP_OK;
}
int xTaskCreate(TaskFunction_t fn, const char *name, unsigned stack, void *arg, unsigned priority, void *handle) {
    if (fail_task) return 0;
    pending_task=fn; return pdPASS;
}
void vTaskDelay(unsigned ticks) { assert(ticks>0); }
void vTaskDelete(void *handle) { ++deleted; }
void esp_rom_delay_us(unsigned us) { assert(us==1000); }
esp_err_t esp_wifi_stop(void) {
    ++stop_calls;
    if (stop_error) return stop_error;
    wifi_started=false; phone_connected=false; return ESP_OK;
}
esp_err_t esp_wifi_start(void) {
    ++start_calls;
    if (start_error) return start_error;
    wifi_started=true; return ESP_OK;
}
esp_err_t esp_wifi_set_mode(wifi_mode_t mode) {
    assert(!wifi_started); ++mode_calls;
    if (mode_error) return mode_error;
    if (restore_error && mode==WIFI_MODE_APSTA) return restore_error;
    wifi_mode=mode; return ESP_OK;
}
esp_err_t esp_wifi_get_channel(uint8_t *channel, wifi_second_chan_t *secondary) {
    *channel=mismatch?1:10; *secondary=WIFI_SECOND_CHAN_NONE; return ESP_OK;
}
esp_err_t esp_wifi_set_channel(uint8_t ch, int secondary) {
    assert(ch==10 && secondary==WIFI_SECOND_CHAN_NONE); ++channel_calls;
    assert(wifi_started);
    /* Reproduce the user's failure with a phone connected to APSTA. */
    if (wifi_mode==WIFI_MODE_APSTA && phone_connected) return ESP_FAIL;
    assert(wifi_mode==WIFI_MODE_STA && !phone_connected);
    return fail_channel ? ESP_FAIL : ESP_OK;
}
esp_err_t esp_wifi_set_promiscuous(bool enabled) { return enabled && fail_promisc ? ESP_FAIL : ESP_OK; }
esp_err_t esp_wifi_80211_tx(int interface, const void *frame, int length, bool sequence) {
    assert(interface==WIFI_IF_STA && frame && length==26 && !sequence);
    ++tx_calls;
    if (tx_calls<=2 && tx_callback && !omit_callbacks) {
        esp_80211_tx_info_t info={.data=(uint8_t *)frame,.data_len=2,.ifidx=interface,
            .tx_status=tx_calls==1?WIFI_SEND_SUCCESS:WIFI_SEND_FAIL};
        tx_callback(&info);
    }
    return tx_calls<=2 ? ESP_OK : ESP_ERR_INVALID_ARG;
}
static void reset(void) {
    fail_task=fail_channel=fail_promisc=false;
    channel_calls=tx_calls=sent=failures=post_retries=deleted=0;
    pending_task=NULL; observed_stage[0]=0; observed_error=ESP_OK; ++current.id;
    wifi_started=phone_connected=true; wifi_mode=WIFI_MODE_APSTA; mismatch=false;
    stop_calls=start_calls=mode_calls=0;
    stop_error=start_error=mode_error=restore_error=ESP_OK;
    register_error=ESP_OK; omit_callbacks=false; tx_callback=NULL;
    current.tx_done_ok=current.tx_done_fail=0; current.tx_callback_registered=false;
}
static void stop_and_check(void) {
    controller_stop(); assert(wifi_started && wifi_mode==WIFI_MODE_APSTA);
    assert(stop_calls==2 && mode_calls==2 && start_calls==2);
}
int main(void) {
    wifi_ap_record_t target={.primary=10,.bssid={2,0,0,0,0,1}};
    assert(controller_start(NULL,1)==ESP_ERR_INVALID_ARG);
    reset(); fail_channel=true;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    assert(channel_calls==1 && tx_calls==0 && failures==1 && deleted==1);
    assert(!strcmp(observed_stage,"channel") && observed_error==ESP_FAIL);
    stop_and_check();
    assert(!current.tx_done_ok && !current.tx_done_fail);
    reset();
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL); stop_and_check();
    assert(current.tx_done_ok==1 && current.tx_done_fail==1 && current.tx_callback_registered && !tx_callback);
    /* A delayed callback after cleanup must not change the stopped snapshot. */
    uint8_t old_frame[26]={0xc0};
    esp_80211_tx_info_t late={.data=old_frame,.data_len=2,.ifidx=WIFI_IF_STA,.tx_status=WIFI_SEND_SUCCESS};
    tx_done(&late); assert(atomic_load(&tx_done_ok)==1);
    reset(); register_error=ESP_FAIL;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL); stop_and_check();
    assert(sent==2 && !current.tx_callback_registered && current.tx_callback_error==ESP_FAIL);
    assert(!current.tx_done_ok && !current.tx_done_fail);
    reset(); omit_callbacks=true;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL); stop_and_check();
    assert(sent==2 && current.tx_callback_registered && !current.tx_done_ok && !current.tx_done_fail);
    reset(); post_retries=2;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    assert(channel_calls==1 && tx_calls==3 && sent==2 && failures==3 && deleted==1);
    assert(!strcmp(observed_stage,"transmit") && observed_error==ESP_ERR_INVALID_ARG);
    stop_and_check();
    reset(); fail_promisc=true;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    assert(!strcmp(observed_stage,"promiscuous")); stop_and_check();
    reset(); fail_task=true;
    assert(controller_start(&target,1)==ESP_ERR_NO_MEM && !pending_task);
    assert(!strcmp(observed_stage,"task")); controller_stop();
    assert(!stop_calls && !mode_calls && !start_calls && phone_connected);
    reset();
    assert(controller_start(&target,1)==ESP_OK);
    assert(controller_start(&target,1)==ESP_ERR_INVALID_ARG);
    /* Request cancellation before scheduling the worker: no further SDK calls. */
    atomic_store(&running,false); pending_task(NULL);
    assert(!tx_calls && !channel_calls && !failures && deleted==1); controller_stop();
    assert(!stop_calls && !mode_calls && !start_calls && phone_connected);
    /* Setup failures must leave enough state for cleanup to restore APSTA. */
    reset(); stop_error=ESP_FAIL;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    assert(!strcmp(observed_stage,"radio_stop")); stop_error=ESP_OK;
    controller_stop(); assert(wifi_started && wifi_mode==WIFI_MODE_APSTA);
    reset(); mode_error=ESP_FAIL;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    assert(!strcmp(observed_stage,"mode")); mode_error=ESP_OK;
    controller_stop(); assert(wifi_started && wifi_mode==WIFI_MODE_APSTA);
    reset(); start_error=ESP_FAIL;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    assert(!strcmp(observed_stage,"radio_start")); start_error=ESP_OK;
    controller_stop(); assert(wifi_started && wifi_mode==WIFI_MODE_APSTA);
    reset(); mismatch=true;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    assert(!tx_calls && !strcmp(observed_stage,"channel_check")); stop_and_check();
    reset();
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    restore_error=ESP_FAIL; controller_stop();
    assert(!strcmp(observed_stage,"restore_mode") && observed_error==ESP_FAIL);
    puts("PASS: actual controller releases APSTA phone channel lock, restores APSTA, rejects channel mismatch, stops on SDK failure, retries queue and handles cancellation/setup failures");
    return 0;
}
