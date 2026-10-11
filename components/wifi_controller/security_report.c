#include "security_report.h"
#include <string.h>

static uint16_t le16(const uint8_t *bytes) {
    return bytes[0] | ((uint16_t)bytes[1] << 8);
}

static bool parse_rsn(const uint8_t *bytes, size_t size, pmf_status_t *pmf) {
    if (size < 8 || le16(bytes) != 1) return false;
    size_t offset = 6; /* Version and group cipher. */
    uint16_t count = le16(bytes + offset);
    offset += 2;
    if (!count || count > (size - offset) / 4) return false;
    offset += (size_t)count * 4;
    if (size - offset < 2) return false;
    count = le16(bytes + offset);
    offset += 2;
    if (!count || count > (size - offset) / 4) return false;
    offset += (size_t)count * 4;
    uint16_t caps = 0;
    if (offset != size) {
        if (size - offset < 2) return false;
        caps = le16(bytes + offset);
        offset += 2;
    }
    /* If present, validate the PMKID count and optional group management cipher. */
    if (offset != size) {
        if (size - offset < 2) return false;
        count = le16(bytes + offset);
        offset += 2;
        if (count > (size - offset) / 16) return false;
        offset += (size_t)count * 16;
        if (size - offset != 0 && size - offset != 4) return false;
    }
    bool required = (caps & (1u << 6)) != 0;
    bool capable = (caps & (1u << 7)) != 0;
    *pmf = required ? (capable ? PMF_REQUIRED : PMF_INCONSISTENT) :
                     (capable ? PMF_CAPABLE : PMF_NOT_ADVERTISED);
    return true;
}

bool security_parse_advertisement(const uint8_t *frame, size_t size,
                                  security_observation_t *result) {
    if (!frame || !result || size < 36 ||
        (frame[0] != 0x80 && frame[0] != 0x50) || (frame[1] & 0x47)) return false;
    security_observation_t parsed = {.pmf = PMF_NOT_ADVERTISED};
    memcpy(parsed.bssid, frame + 16, 6);
    size_t offset = 36; /* Management MAC header and beacon fixed parameters. */
    while (offset < size) {
        if (size - offset < 2) return false;
        uint8_t type = frame[offset], length = frame[offset + 1];
        offset += 2;
        if (length > size - offset) return false;
        if (type == 0) {
            if (parsed.ssid_seen || length > 32) return false;
            parsed.ssid_seen = true; parsed.ssid_len = length;
            memcpy(parsed.ssid, frame + offset, length);
        }
        if (type == 48) {
            if (parsed.rsn_seen || !parse_rsn(frame + offset, length, &parsed.pmf)) return false;
            parsed.rsn_seen = true;
        }
        offset += length;
    }
    *result = parsed;
    return true;
}

const char *security_pmf_name(pmf_status_t status) {
    switch (status) {
        case PMF_NOT_ADVERTISED: return "Not advertised";
        case PMF_CAPABLE: return "Supported, optional";
        case PMF_REQUIRED: return "Required";
        case PMF_INCONSISTENT: return "Inconsistent advertisement";
        default: return "Unknown (no valid advertisement observed)";
    }
}
