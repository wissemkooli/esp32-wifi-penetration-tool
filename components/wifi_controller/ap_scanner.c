#include "ap_scanner.h"
#include "security_report.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include <string.h>

static wifictl_ap_records_t ap_records;
static security_observation_t observations[64];
static unsigned observation_count;
static bool observing;
static portMUX_TYPE observation_lock = portMUX_INITIALIZER_UNLOCKED;

static void scan_frame(void *data, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT || !data) return;
    wifi_promiscuous_pkt_t *packet = data;
    if (packet->rx_ctrl.sig_len < 4) return;
    security_observation_t observation;
    if (!security_parse_advertisement(packet->payload, packet->rx_ctrl.sig_len - 4, &observation)) return;
    portENTER_CRITICAL(&observation_lock);
    if (observing) {
        unsigned i;
        for (i = 0; i < observation_count; ++i)
            if (!memcmp(observations[i].bssid, observation.bssid, 6)) break;
        if (i < 64) {
            observations[i] = observation;
            if (i == observation_count) ++observation_count;
        }
    }
    portEXIT_CRITICAL(&observation_lock);
}

esp_err_t wifictl_scan_nearby_aps(void) {
    ap_records.count = 0;
    portENTER_CRITICAL(&observation_lock);
    observation_count = 0;
    observing = true;
    portEXIT_CRITICAL(&observation_lock);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_err_t err = esp_wifi_set_promiscuous_filter(&filter);
    if (err == ESP_OK) err = esp_wifi_set_promiscuous_rx_cb(scan_frame);
    if (err == ESP_OK) err = esp_wifi_set_promiscuous(true);
    if (err == ESP_OK) {
        wifi_scan_config_t config = {.show_hidden = true, .scan_type = WIFI_SCAN_TYPE_PASSIVE,
                                     .scan_time.passive = 200};
        err = esp_wifi_scan_start(&config, true);
    }
    portENTER_CRITICAL(&observation_lock);
    observing = false;
    portEXIT_CRITICAL(&observation_lock);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    if (err != ESP_OK) return err;
    ap_records.count = CONFIG_SCAN_MAX_AP;
    err = esp_wifi_scan_get_ap_records(&ap_records.count, ap_records.records);
    if (err != ESP_OK) ap_records.count = 0;
    return err;
}

const wifictl_ap_records_t *wifictl_get_ap_records(void) { return &ap_records; }
const wifi_ap_record_t *wifictl_get_ap_record(unsigned index) {
    return index < ap_records.count ? &ap_records.records[index] : NULL;
}
unsigned wifictl_get_ap_ssid(unsigned index, uint8_t out[32]) {
    const wifi_ap_record_t *ap = wifictl_get_ap_record(index);
    if (!ap) return 0;
    unsigned size = strnlen((const char *)ap->ssid, 32);
    memcpy(out, ap->ssid, size);
    portENTER_CRITICAL(&observation_lock);
    for (unsigned i = 0; i < observation_count; ++i) {
        if (!memcmp(ap->bssid, observations[i].bssid, 6) && observations[i].ssid_seen && observations[i].ssid_len) {
            size = observations[i].ssid_len; memcpy(out, observations[i].ssid, size); break;
        }
    }
    portEXIT_CRITICAL(&observation_lock);
    return size;
}

pmf_status_t wifictl_get_ap_pmf(unsigned index) {
    const wifi_ap_record_t *ap = wifictl_get_ap_record(index);
    if (!ap) return PMF_UNKNOWN;
    pmf_status_t status = PMF_UNKNOWN;
    portENTER_CRITICAL(&observation_lock);
    for (unsigned i = 0; i < observation_count; ++i) {
        if (!memcmp(ap->bssid, observations[i].bssid, 6)) {
            status = observations[i].pmf;
            break;
        }
    }
    portEXIT_CRITICAL(&observation_lock);
    return status;
}

const char *wifictl_auth_name(wifi_auth_mode_t auth) {
    switch (auth) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP (legacy)";
        case WIFI_AUTH_WPA_PSK: return "WPA-Personal (legacy)";
        case WIFI_AUTH_WPA2_PSK: return "WPA2-Personal";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2-Personal mixed";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Enterprise";
        case WIFI_AUTH_WPA3_PSK: return "WPA3-Personal";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3-Personal transition";
        case WIFI_AUTH_WAPI_PSK: return "WAPI";
        case WIFI_AUTH_OWE: return "Enhanced Open (OWE)";
        case WIFI_AUTH_WPA3_ENT_192: return "WPA3-Enterprise 192-bit";
        case WIFI_AUTH_WPA3_EXT_PSK:
        case WIFI_AUTH_WPA3_EXT_PSK_MIXED_MODE: return "WPA3-Personal";
        case WIFI_AUTH_DPP: return "DPP";
        case WIFI_AUTH_WPA3_ENTERPRISE: return "WPA3-Enterprise";
        case WIFI_AUTH_WPA2_WPA3_ENTERPRISE: return "WPA2/WPA3-Enterprise transition";
        case WIFI_AUTH_WPA_ENTERPRISE: return "WPA-Enterprise (legacy)";
        default: return "Unknown";
    }
}
