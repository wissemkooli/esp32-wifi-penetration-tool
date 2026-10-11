#pragma once
#include <stdint.h>
#include <stdbool.h>
typedef struct { uint16_t sig_len; uint32_t timestamp; } wifi_pkt_rx_ctrl_t;
typedef struct { wifi_pkt_rx_ctrl_t rx_ctrl; uint8_t payload[]; } wifi_promiscuous_pkt_t;
typedef struct { uint8_t ssid[33], bssid[6], primary; int8_t rssi; int authmode; } wifi_ap_record_t;
