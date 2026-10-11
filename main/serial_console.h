#pragma once
#include <stddef.h>
void serial_console_execute(const char *line, char *response, size_t capacity);
void serial_console_start(void);
