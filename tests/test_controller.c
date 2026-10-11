/* Exercise the actual producer using a deferred task and injected SDK failures. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../main/controller.c"

static attack_job_t current = {.id=7};
static TaskFunction_t pending_task;
static bool fail_task, fail_channel, fail_promisc;
static unsigned channel_calls, tx_calls, sent, failures, post_retries, deleted;
static char observed_stage[16];
static esp_err_t observed_error;
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
esp_err_t esp_wifi_set_channel(uint8_t ch, int secondary) {
    assert(ch==10 && secondary==WIFI_SECOND_CHAN_NONE); ++channel_calls;
    return fail_channel ? ESP_FAIL : ESP_OK;
}
esp_err_t esp_wifi_set_promiscuous(bool enabled) { return enabled && fail_promisc ? ESP_FAIL : ESP_OK; }
esp_err_t esp_wifi_80211_tx(int interface, const void *frame, int length, bool sequence) {
    assert(interface==WIFI_IF_STA && frame && length==26 && !sequence);
    ++tx_calls;
    return tx_calls<=2 ? ESP_OK : ESP_ERR_INVALID_ARG;
}
static void reset(void) {
    fail_task=fail_channel=fail_promisc=false;
    channel_calls=tx_calls=sent=failures=post_retries=deleted=0;
    pending_task=NULL; observed_stage[0]=0; observed_error=ESP_OK; ++current.id;
}
int main(void) {
    wifi_ap_record_t target={.primary=10,.bssid={2,0,0,0,0,1}};
    assert(controller_start(NULL,1)==ESP_ERR_INVALID_ARG);
    reset(); fail_channel=true;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    assert(channel_calls==1 && tx_calls==0 && failures==1 && deleted==1);
    assert(!strcmp(observed_stage,"channel") && observed_error==ESP_FAIL);
    controller_stop();
    reset(); post_retries=2;
    assert(controller_start(&target,1)==ESP_OK); pending_task(NULL);
    assert(channel_calls==1 && tx_calls==3 && sent==2 && failures==3 && deleted==1);
    assert(!strcmp(observed_stage,"transmit") && observed_error==ESP_ERR_INVALID_ARG);
    controller_stop();
    reset(); fail_promisc=true;
    assert(controller_start(&target,1)==ESP_FAIL && !pending_task);
    assert(!strcmp(observed_stage,"promiscuous")); controller_stop();
    reset(); fail_task=true;
    assert(controller_start(&target,1)==ESP_ERR_NO_MEM && !pending_task);
    assert(!strcmp(observed_stage,"task")); controller_stop();
    reset();
    assert(controller_start(&target,1)==ESP_OK);
    assert(controller_start(&target,1)==ESP_ERR_INVALID_ARG);
    /* Request cancellation before scheduling the worker: no further SDK calls. */
    atomic_store(&running,false); pending_task(NULL);
    assert(!tx_calls && !channel_calls && !failures && deleted==1); controller_stop();
    puts("PASS: actual controller stops on channel/TX failures, exact stage/code, queue retries, setup failure and cancellation");
    return 0;
}
