#pragma once
#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
#define portMAX_DELAY UINT32_MAX
typedef const char *esp_event_base_t;
typedef void (*esp_event_handler_t)(void *, esp_event_base_t, int32_t, void *);
#define ESP_EVENT_DECLARE_BASE(name) extern esp_event_base_t name
#define ESP_EVENT_DEFINE_BASE(name) esp_event_base_t name = #name
#define ESP_EVENT_ANY_BASE NULL
#define ESP_EVENT_ANY_ID -1
esp_err_t esp_event_post(esp_event_base_t, int32_t, const void *, size_t, unsigned);
esp_err_t esp_event_handler_register(esp_event_base_t, int32_t, esp_event_handler_t, void *);
esp_err_t esp_event_handler_unregister(esp_event_base_t, int32_t, esp_event_handler_t);
