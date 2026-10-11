#pragma once
#include <stdio.h>
#define ESP_LOG_ERROR 0
#define ESP_LOG_DEBUG 0
#define ESP_LOG_VERBOSE 0
#define ESP_LOGE(tag, fmt, ...) do { (void)(tag); if (0) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGW ESP_LOGE
#define ESP_LOGI ESP_LOGE
#define ESP_LOGD ESP_LOGE
#define ESP_LOGV ESP_LOGE
