#include "serial_console.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include <stdbool.h>
static void console_task(void *arg) {
    char line[96], response[2048]; unsigned length=0; bool overflow=false;
    puts("Unified serial controller: help for commands (115200 baud)");
    for (;;) {
        int ch=getchar();
        if(ch==EOF) { clearerr(stdin); vTaskDelay(pdMS_TO_TICKS(10)); continue; }
        if(ch=='\r' || ch=='\n') {
            if(overflow) puts("error: command too long");
            else if(length) { line[length]=0; serial_console_execute(line,response,sizeof(response)); puts(response); }
            length=0; overflow=false;
        } else if(length<sizeof(line)-1 && !overflow) line[length++]=ch;
        else overflow=true;
    }
}
void serial_console_start(void) {
    setvbuf(stdin,NULL,_IONBF,0);
    xTaskCreate(console_task,"serial-console",6144,NULL,3,NULL);
}
