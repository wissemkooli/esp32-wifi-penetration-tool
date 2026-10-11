#pragma once
#include "FreeRTOS.h"
#include <stddef.h>
typedef void (*TaskFunction_t)(void *);
int xTaskCreate(TaskFunction_t fn, const char *name, unsigned stack, void *arg, unsigned priority, void *handle);
void vTaskDelay(unsigned ticks);
void vTaskDelete(void *handle);
