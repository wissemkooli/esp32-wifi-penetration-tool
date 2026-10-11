/**
 * @file frame_analyzer_parser.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements parsing functionality
 */
#include "frame_analyzer_parser.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_wifi_types.h"

#include "frame_analyzer_types.h"





/**
 * @brief Debug function to print raw frame to serial
 * 
 * @param frame 
 */
void print_raw_frame(const wifi_promiscuous_pkt_t *frame){
    for(unsigned i = 0; i < frame->rx_ctrl.sig_len; i++) {
        printf("%02x", frame->payload[i]);
    }
    printf("\n");
}

/**
 * @brief Debug functions to print MAC address from given buffer to serial
 * 
 * @param a mac address buffer
 */
void print_mac_address(const uint8_t *a){
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
    a[0], a[1], a[2], a[3], a[4], a[5]);
    printf("\n");
}

bool is_frame_bssid_matching(wifi_promiscuous_pkt_t *frame, uint8_t *bssid) {
    if (!frame || !bssid || frame->rx_ctrl.sig_len < 28) return false;
    const uint8_t *bytes = frame->payload;
    unsigned ds = bytes[1] & 3;
    if (ds == 3) return false; /* Four-address traffic has no BSSID field. */
    unsigned offset = ds == 1 ? 4 : ds == 2 ? 10 : 16;
    return memcmp(bytes + offset, bssid, 6) == 0;
}

eapol_packet_t *parse_eapol_packet(data_frame_t *frame, size_t frame_size) {
    if (!frame || frame_size < 24) return NULL;
    uint8_t *bytes = (uint8_t *)frame;
    /* Only unfragmented, unprotected data frames are supported. */
    if ((bytes[0] & 0x0f) != 0x08 || (bytes[0] & 0x40) ||
        (bytes[1] & 0x44) || (bytes[22] & 0x0f)) return NULL;
    if ((bytes[1] & 3) == 3) return NULL;
    size_t offset = 24;
    if (bytes[0] & 0x80) {
        if (frame_size - offset < 2 || (bytes[offset] & 0x80)) return NULL;
        offset += 2; /* QoS control; aggregated MSDUs are not parsed. */
        if (bytes[1] & 0x80) offset += 4; /* HT control. */
    }
    static const uint8_t llc_eapol[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
    if (offset > frame_size || frame_size - offset < sizeof(llc_eapol) + 4)
        return NULL;
    if (memcmp(bytes + offset, llc_eapol, sizeof(llc_eapol))) return NULL;
    offset += sizeof(llc_eapol);
    uint16_t body_size = frame_read_be16(bytes + offset + 2);
    if (body_size > frame_size - offset - 4) return NULL;
    return (eapol_packet_t *)(bytes + offset);
}

eapol_key_packet_t *parse_eapol_key_packet(eapol_packet_t *packet, size_t packet_size) {
    if (!packet || packet_size < sizeof(packet->header) ||
        packet->header.packet_type != EAPOL_KEY) return NULL;
    size_t body_size = frame_read_be16(&packet->header.packet_body_length);
    if (body_size < sizeof(eapol_key_packet_t) ||
        body_size > packet_size - sizeof(packet->header)) return NULL;
    eapol_key_packet_t *key = (eapol_key_packet_t *)packet->packet_body;
    if (key->descriptor_type != 2 && key->descriptor_type != 254) return NULL;
    if (frame_read_be16(&key->key_data_length) > body_size - sizeof(*key)) return NULL;
    return key;
}

void free_pmkid_list(pmkid_item_t *head) {
    while (head) {
        pmkid_item_t *next = head->next;
        free(head);
        head = next;
    }
}

pmkid_item_t *parse_pmkid(eapol_key_packet_t *key, size_t packet_size) {
    if (!key || packet_size < sizeof(*key)) return NULL;
    size_t remaining = frame_read_be16(&key->key_data_length);
    uint16_t info = frame_read_be16(&key->key_information);
    if (!remaining || remaining > packet_size - sizeof(*key) || (info & 0x1000))
        return NULL;
    const uint8_t *cursor = key->key_data;
    pmkid_item_t *head = NULL;
    while (remaining) {
        if (remaining < 2 || cursor[1] > remaining - 2) goto malformed;
        size_t element_size = (size_t)cursor[1] + 2;
        static const uint8_t pmkid_selector[] = {0x00, 0x0f, 0xac, 0x04};
        if (cursor[0] == KEY_DATA_TYPE && cursor[1] >= 4 &&
            memcmp(cursor + 2, pmkid_selector, sizeof(pmkid_selector)) == 0) {
            if (cursor[1] != 20) goto malformed;
            pmkid_item_t *item = malloc(sizeof(*item));
            if (!item) goto malformed;
            memcpy(item->pmkid, cursor + 6, sizeof(item->pmkid));
            item->next = head;
            head = item;
        }
        cursor += element_size;
        remaining -= element_size;
    }
    return head;
malformed:
    free_pmkid_list(head);
    return NULL;
}
