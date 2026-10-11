#pragma once
#include "esp_wifi_types.h"
#include "esp_err.h"
enum { WIFI_SECOND_CHAN_NONE=0, WIFI_IF_STA=0 };
esp_err_t esp_wifi_set_channel(uint8_t channel, int secondary);
esp_err_t esp_wifi_set_promiscuous(bool enabled);
esp_err_t esp_wifi_80211_tx(int interface, const void *frame, int length, bool sequence);
