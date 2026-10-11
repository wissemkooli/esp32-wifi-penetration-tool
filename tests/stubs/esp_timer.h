#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
typedef struct mock_timer *esp_timer_handle_t;
typedef struct { void (*callback)(void *); const char *name; void *arg; } esp_timer_create_args_t;
esp_err_t esp_timer_create(const esp_timer_create_args_t *, esp_timer_handle_t *);
esp_err_t esp_timer_start_once(esp_timer_handle_t, uint64_t);
esp_err_t esp_timer_stop(esp_timer_handle_t);
int64_t esp_timer_get_time(void);
