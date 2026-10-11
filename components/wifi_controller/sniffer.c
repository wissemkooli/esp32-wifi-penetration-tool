/**
 * @file sniffer.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements sniffer logic.
 */
#include "sniffer.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

static const char *TAG = "sniffer"; 

ESP_EVENT_DEFINE_BASE(SNIFFER_EVENTS);
static atomic_uint generation;
static atomic_bool capturing;
uint32_t wifictl_sniffer_generation(void) { return atomic_load(&generation); }

/**
 * @brief Callback for promiscuous reciever. 
 * 
 * It forwards captured frames into event pool and sorts them based on their type
 * - Data
 * - Management
 * - Control
 * 
 * @param buf 
 * @param type 
 */
static void frame_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!buf || !atomic_load(&capturing)) return;
    uint32_t run = atomic_load(&generation);

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) buf;

    int32_t event_id;
    switch (type) {
        case WIFI_PKT_DATA:
            event_id = SNIFFER_EVENT_CAPTURED_DATA;
            break;
        case WIFI_PKT_MGMT:
            event_id = SNIFFER_EVENT_CAPTURED_MGMT;
            break;
        case WIFI_PKT_CTRL:
            event_id = SNIFFER_EVENT_CAPTURED_CTRL;
            break;
        default:
            return;
    }

    size_t packet_size = sizeof(*frame) + frame->rx_ctrl.sig_len;
    sniffer_frame_t *event = malloc(sizeof(*event) + packet_size);
    if (!event) return;
    event->generation = run;
    memcpy(event->packet, frame, packet_size);
    /* The Wi-Fi driver callback must never wait for a full application queue. */
    esp_event_post(SNIFFER_EVENTS, event_id, event, sizeof(*event) + packet_size, 0);
    free(event);
}

/**
 * @see https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/network/esp_wifi.html#_CPPv425wifi_promiscuous_filter_t
 */
esp_err_t wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl) {
    wifi_promiscuous_filter_t filter = { .filter_mask = 0 };
    if(data) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    }
    if(mgmt) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    }
    if(ctrl) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    }
    return esp_wifi_set_promiscuous_filter(&filter);
}

esp_err_t wifictl_sniffer_start(uint8_t channel) {
    ESP_LOGI(TAG, "Starting promiscuous mode...");
    // ESP32 cannot switch port, if there is some STA connected to AP
    ESP_LOGD(TAG, "Kicking all connected STAs from AP");
    uint8_t previous; wifi_second_chan_t second;
    esp_err_t err = esp_wifi_get_channel(&previous, &second);
    if (err != ESP_OK) return err;
    if (previous != channel) {
        err = esp_wifi_deauth_sta(0);
        if (err != ESP_OK) return err;
    }
    err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) return err;
    atomic_fetch_add(&generation, 1);
    err = esp_wifi_set_promiscuous_rx_cb(&frame_handler);
    if (err != ESP_OK) return err;
    atomic_store(&capturing, true);
    err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        atomic_store(&capturing, false);
        ESP_LOGE(TAG, "Cannot start sniffer: %s", esp_err_to_name(err));
    }
    return err;
}

void wifictl_sniffer_stop() {
    ESP_LOGI(TAG, "Stopping promiscuous mode...");
    atomic_store(&capturing, false);
    esp_wifi_set_promiscuous(false);
}
