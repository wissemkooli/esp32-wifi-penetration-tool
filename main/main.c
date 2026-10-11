/**
 * @file main.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Main file used to setup ESP32 into initial state
 * 
 * Starts management AP and webserver  
 */

#include <stdio.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_app_desc.h"

#include "attack.h"
#include "wifi_controller.h"
#include "webserver.h"
#include "serial_console.h"

static const char* TAG = "main";

void app_main(void)
{
    ESP_LOGD(TAG, "app_main started");
    const esp_app_desc_t *app = esp_app_get_description();
    ESP_LOGI(TAG, "Firmware %s; ESP-IDF %s; target esp32", app->version, app->idf_ver);
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifictl_mgmt_ap_start();
    attack_init();
    webserver_run();
    serial_console_start();
}
