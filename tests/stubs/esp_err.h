#pragma once
#include <assert.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_ERR_TIMEOUT 0x107
#define ESP_ERROR_CHECK(expr) assert((expr) == ESP_OK)
#define ESP_ERROR_CHECK_WITHOUT_ABORT(expr) ((void)(expr))
static inline const char *esp_err_to_name(int err) { (void)err; return "mock error"; }
