#pragma once
#include "esp_wifi_types.h"
#include "esp_err.h"
typedef int wifi_second_chan_t;
typedef int wifi_mode_t;
enum { WIFI_SECOND_CHAN_NONE=0, WIFI_IF_STA=0, WIFI_MODE_STA=1, WIFI_MODE_APSTA=3 };
enum { WIFI_SEND_SUCCESS=0, WIFI_SEND_FAIL=1 };
typedef struct { uint8_t *data; uint8_t data_len; int ifidx, tx_status; } esp_80211_tx_info_t;
typedef void (*esp_wifi_80211_tx_done_cb_t)(const esp_80211_tx_info_t *info);
esp_err_t esp_wifi_register_80211_tx_cb(esp_wifi_80211_tx_done_cb_t cb);
esp_err_t esp_wifi_stop(void);
esp_err_t esp_wifi_start(void);
esp_err_t esp_wifi_set_mode(wifi_mode_t mode);
esp_err_t esp_wifi_get_channel(uint8_t *channel, wifi_second_chan_t *secondary);
esp_err_t esp_wifi_set_channel(uint8_t channel, int secondary);
esp_err_t esp_wifi_set_promiscuous(bool enabled);
esp_err_t esp_wifi_80211_tx(int interface, const void *frame, int length, bool sequence);
