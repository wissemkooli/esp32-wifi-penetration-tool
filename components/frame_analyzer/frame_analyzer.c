#include "frame_analyzer.h"
#include "frame_analyzer_parser.h"
#include "wifi_controller.h"
#include "esp_log.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
static const char *TAG = "frame_analyzer";
static uint8_t target_bssid[6];
static search_type_t search_type;
static bool active;
ESP_EVENT_DEFINE_BASE(FRAME_ANALYZER_EVENTS);

static void data_frame_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    sniffer_frame_t *event = data;
    if (!active || event->generation != wifictl_sniffer_generation()) return;
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *)event->packet;
    if (!is_frame_bssid_matching(frame, target_bssid)) return;
    /* ESP-IDF sig_len includes the four-byte FCS. */
    size_t frame_size = frame->rx_ctrl.sig_len - 4;
    eapol_packet_t *packet = parse_eapol_packet((data_frame_t *)frame->payload, frame_size);
    if (!packet) return;
    size_t body_size = frame_read_be16(&packet->header.packet_body_length);
    eapol_key_packet_t *key = parse_eapol_key_packet(packet, sizeof(packet->header) + body_size);
    if (!key) return;
    if (search_type == SEARCH_HANDSHAKE) {
        esp_event_post(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME,
            event, sizeof(*event) + sizeof(*frame) + frame->rx_ctrl.sig_len, 0);
        return;
    }
    /* PMKID KDEs belong to the station addressed by an AP's first key message. */
    uint16_t info = frame_read_be16(&key->key_information);
    if ((frame->payload[1] & 3) != 2 || (info & 0x1388) != 0x0088) return;
    pmkid_item_t *head = parse_pmkid(key, body_size);
    if (!head) return;
    unsigned count = 0;
    for (pmkid_item_t *item = head; item; item = item->next) ++count;
    size_t result_size = sizeof(pmkid_result_t) + count * 16;
    pmkid_result_t *result = malloc(result_size);
    if (result) {
        result->generation = event->generation;
        result->count = count;
        memcpy(result->station, frame->payload + 4, 6);
        unsigned i = 0;
        for (pmkid_item_t *item = head; item; item = item->next, ++i)
            memcpy(result->pmkids + i * 16, item->pmkid, 16);
        /* esp_event copies the entire result; discarded events cannot leak lists. */
        esp_event_post(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, result, result_size, 0);
        free(result);
    }
    free_pmkid_list(head);
}

void frame_analyzer_capture_start(search_type_t type, const uint8_t *bssid) {
    search_type = type;
    memcpy(target_bssid, bssid, sizeof(target_bssid));
    ESP_ERROR_CHECK(esp_event_handler_register(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA,
                                             data_frame_handler, NULL));
    active = true;
}

void frame_analyzer_capture_stop(void) {
    if (!active) return;
    active = false;
    esp_err_t err = esp_event_handler_unregister(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA,
                                               data_frame_handler);
    if (err != ESP_OK) ESP_LOGW(TAG, "Handler cleanup: %s", esp_err_to_name(err));
}
