#pragma once
#include "attack.h"
esp_err_t controller_start(const wifi_ap_record_t *targets, unsigned count);
void controller_stop(void);
