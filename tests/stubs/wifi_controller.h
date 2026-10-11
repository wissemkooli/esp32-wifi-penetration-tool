#pragma once
#define CONFIG_MGMT_AP_SSID "ManagementAP"
#include "esp_wifi_types.h"
#include "esp_event.h"
#include "security_report.h"
typedef struct { uint32_t generation; uint8_t packet[]; } sniffer_frame_t;
typedef struct { uint16_t count; wifi_ap_record_t records[20]; } wifictl_ap_records_t;
ESP_EVENT_DECLARE_BASE(SNIFFER_EVENTS);
enum { SNIFFER_EVENT_CAPTURED_DATA, SNIFFER_EVENT_CAPTURED_MGMT, SNIFFER_EVENT_CAPTURED_CTRL };
const wifi_ap_record_t *wifictl_get_ap_record(unsigned);
const wifictl_ap_records_t *wifictl_get_ap_records(void);
esp_err_t wifictl_scan_nearby_aps(void);
pmf_status_t wifictl_get_ap_pmf(unsigned);
unsigned wifictl_get_ap_ssid(unsigned, uint8_t out[32]);
const char *wifictl_auth_name(int);
uint32_t wifictl_sniffer_generation(void);
esp_err_t wifictl_sniffer_start(uint8_t);
void wifictl_sniffer_stop(void);
esp_err_t wifictl_sniffer_filter_frame_types(bool, bool, bool);
void wifictl_mgmt_ap_start(void);
void wifictl_restore_ap_mac(void);
void wifictl_get_sta_mac(uint8_t *);
esp_err_t wifictl_sta_connect_to_ap(const wifi_ap_record_t *, const char *);
void wifictl_sta_disconnect(void);
