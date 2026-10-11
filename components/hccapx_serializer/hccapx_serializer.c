/** Serialize a validated WPA/WPA2 message pair. No radio operations here. */
#include "hccapx_serializer.h"
#include "frame_analyzer_parser.h"
#include <stdbool.h>
#include <string.h>

#define HCCAPX_SIGNATURE 0x58504348
#define NO_MESSAGE_PAIR 255
static hccapx_t hccapx;
static unsigned ap_message, ap_keyver;
static bool have_m2;
static bool initialized;
static uint8_t ap_replay[8], sta_replay[8];

static bool all_zero(const uint8_t *bytes, size_t size) {
    for (size_t i = 0; i < size; ++i) if (bytes[i]) return false;
    return true;
}

void hccapx_serializer_init(const uint8_t *ssid, unsigned size) {
    memset(&hccapx, 0, sizeof(hccapx));
    hccapx.signature = HCCAPX_SIGNATURE;
    hccapx.version = 4;
    hccapx.message_pair = NO_MESSAGE_PAIR;
    ap_message = ap_keyver = 0;
    have_m2 = false;
    memset(ap_replay, 0, sizeof(ap_replay));
    memset(sta_replay, 0, sizeof(sta_replay));
    initialized = ssid != NULL && size <= sizeof(hccapx.essid);
    if (initialized) {
        hccapx.essid_len = size;
        memcpy(hccapx.essid, ssid, size);
    }
}

hccapx_t *hccapx_serializer_get(void) {
    return initialized && hccapx.message_pair != NO_MESSAGE_PAIR ? &hccapx : NULL;
}

static bool replay_matches(void) {
    uint8_t expected[8];
    memcpy(expected, sta_replay, sizeof(expected));
    if (ap_message == 3) {
        for (int i = 7; i >= 0; --i) if (++expected[i]) break;
    }
    return memcmp(expected, ap_replay, sizeof(expected)) == 0;
}

void hccapx_serializer_add_frame(data_frame_t *frame, size_t frame_size) {
    if (!initialized) return;
    eapol_packet_t *packet = parse_eapol_packet(frame, frame_size);
    if (!packet) return;
    size_t packet_size = sizeof(packet->header) + frame_read_be16(&packet->header.packet_body_length);
    eapol_key_packet_t *key = parse_eapol_key_packet(packet, packet_size);
    if (!key) return;
    uint16_t info = frame_read_be16(&key->key_information);
    unsigned version = info & 7;
    if (!(info & 8) || (info & 0x0c00) || version < 1 || version > 3) return;
    const uint8_t *bytes = (const uint8_t *)frame;
    bool from_ap = (bytes[1] & 3) == 2;
    bool from_sta = (bytes[1] & 3) == 1;
    if (!from_ap && !from_sta) return;
    bool ack = (info & 0x80) != 0, mic = (info & 0x100) != 0;
    if (from_ap != ack || all_zero(key->key_nonce, sizeof(key->key_nonce))) return;
    if (from_sta && (!mic || (info & 0x200))) return; /* M4 has no SNonce. */
    const uint8_t *ap = from_ap ? bytes + 10 : bytes + 4;
    const uint8_t *sta = from_ap ? bytes + 4 : bytes + 10;
    if (!all_zero(hccapx.mac_ap, 6) &&
        (memcmp(ap, hccapx.mac_ap, 6) || memcmp(sta, hccapx.mac_sta, 6))) return;
    memcpy(hccapx.mac_ap, ap, 6);
    memcpy(hccapx.mac_sta, sta, 6);
    if (from_ap) {
        /* Save ANonce from M3 too when M1 was not captured. */
        if (ap_message && memcmp(hccapx.nonce_ap, key->key_nonce, 32)) have_m2 = false;
        ap_message = mic ? 3 : 1;
        ap_keyver = version;
        memcpy(hccapx.nonce_ap, key->key_nonce, 32);
        memcpy(ap_replay, key->key_replay_counter, 8);
    } else {
        if (packet_size > sizeof(hccapx.eapol)) return;
        have_m2 = true;
        hccapx.keyver = version;
        hccapx.eapol_len = packet_size;
        memset(hccapx.eapol, 0, sizeof(hccapx.eapol));
        memcpy(hccapx.eapol, packet, packet_size);
        memcpy(hccapx.keymic, key->key_mic, 16);
        memset(hccapx.eapol + 81, 0, 16);
        memcpy(hccapx.nonce_sta, key->key_nonce, 32);
        memcpy(sta_replay, key->key_replay_counter, 8);
    }
    hccapx.message_pair = NO_MESSAGE_PAIR;
    if (have_m2 && ap_message && ap_keyver == hccapx.keyver && replay_matches())
        hccapx.message_pair = ap_message == 1 ? 0 : 2;
}
