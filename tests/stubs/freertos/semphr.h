#pragma once
#include <assert.h>
typedef int *SemaphoreHandle_t;
static inline SemaphoreHandle_t xSemaphoreCreateRecursiveMutex(void) { static int count; return &count; }
static inline int xSemaphoreTakeRecursive(SemaphoreHandle_t lock, unsigned timeout) { (void)timeout; ++*lock; return 1; }
static inline int xSemaphoreGiveRecursive(SemaphoreHandle_t lock) { assert(*lock > 0); --*lock; return 1; }
static inline SemaphoreHandle_t xSemaphoreCreateBinary(void) { static int ready; ready=0; return &ready; }
static inline int xSemaphoreTake(SemaphoreHandle_t lock, unsigned timeout) {
    if (!*lock) { assert(timeout == 0); return 0; }
    *lock=0; return 1;
}
static inline int xSemaphoreGive(SemaphoreHandle_t lock) { *lock=1; return 1; }
