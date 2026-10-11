#pragma once
#include "esp_wifi_types.h"
#include "esp_err.h"
typedef int wifi_second_chan_t;
typedef int wifi_mode_t;
enum { WIFI_SECOND_CHAN_NONE=0, WIFI_IF_STA=0, WIFI_MODE_STA=1, WIFI_MODE_APSTA=3 };
esp_err_t esp_wifi_stop(void);
esp_err_t esp_wifi_start(void);
esp_err_t esp_wifi_set_mode(wifi_mode_t mode);
esp_err_t esp_wifi_get_channel(uint8_t *channel, wifi_second_chan_t *secondary);
esp_err_t esp_wifi_set_channel(uint8_t channel, int secondary);
esp_err_t esp_wifi_set_promiscuous(bool enabled);
esp_err_t esp_wifi_80211_tx(int interface, const void *frame, int length, bool sequence);
