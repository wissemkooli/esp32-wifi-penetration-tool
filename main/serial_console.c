#include "serial_console.h"
#include "attack.h"
#include "wifi_controller.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static uint8_t selected[MAX_JOB_TARGETS], duration = 30;
static unsigned selected_count;
static uint32_t selection_scan;

static bool parse_number(const char *text, unsigned max, unsigned *out, const char **end) {
    if (!isdigit((unsigned char)*text)) return false;
    unsigned value = 0;
    do {
        unsigned digit = *text++ - '0';
        if (value > (max - digit) / 10 || digit > max) return false;
        value = value * 10 + digit;
    } while (isdigit((unsigned char)*text));
    *out = value; *end = text; return true;
}
void serial_console_execute(const char *line, char *out, size_t capacity) {
    if (!line || !out || !capacity) return;
    while (*line == ' ') ++line;
    size_t length = strlen(line); while (length && isspace((unsigned char)line[length-1])) --length;
    char command[96];
    if (length >= sizeof(command)) { snprintf(out, capacity, "error: command too long"); return; }
    memcpy(command, line, length); command[length] = 0;
    esp_err_t err = ESP_OK;
    attack_lock(); const attack_job_t *job = attack_get_job();
    if (!strcmp(command, "scan")) err = attack_scan_submit();
    else if (!strcmp(command, "status")) {
        snprintf(out, capacity, "session=%s job=%lu state=%u scanning=%d accepted=%lu err=%lu channel_err=%lu selected=%u reason=%s stage=%s error=%s (0x%x) driver_ok=%lu driver_fail=%lu callback=%d callback_error=%s",
            job->boot_id, (unsigned long)job->id, attack_get_status()->state, job->scanning,
            (unsigned long)job->sent, (unsigned long)job->tx_errors, (unsigned long)job->channel_errors,
            selected_count, job->reason, job->radio_stage,
            job->radio_error ? esp_err_to_name(job->radio_error) : "ESP_OK", (unsigned)job->radio_error,
            (unsigned long)job->tx_done_ok, (unsigned long)job->tx_done_fail,
            job->tx_callback_registered, esp_err_to_name(job->tx_callback_error));
        attack_unlock(); return;
    } else if (!strcmp(command, "start")) {
        err = attack_submit_job(selected, selected_count, ATTACK_TYPE_CONTROLLER, 0, duration, selection_scan);
    } else if (!strcmp(command, "stop")) err = attack_stop_request(job->boot_id, job->id);
    else if (!strcmp(command, "cancel")) {
        if (attack_is_running() && !job->scanning) err = attack_stop_request(job->boot_id, job->id);
        else if (job->scanning) err = ESP_ERR_INVALID_STATE;
        if (err == ESP_OK) selected_count = 0;
    } else if (!strncmp(command, "limit ", 6)) {
        unsigned value; const char *end;
        if (!parse_number(command + 6, 255, &value, &end) || *end || !value) err = ESP_ERR_INVALID_ARG;
        else duration = value;
    } else if (!strcmp(command, "help")) {
        snprintf(out, capacity, "scan | list | all | <i,j,k> | start | stop | status | limit <1..255> | cancel");
        attack_unlock(); return;
    } else if (!strcmp(command, "list")) {
        size_t used = 0; const wifictl_ap_records_t *aps = wifictl_get_ap_records();
        out[0]=0;
        if (job->scanning) err = ESP_ERR_INVALID_STATE;
        else for (unsigned i = 0; i < aps->count && used < capacity; ++i) {
            const wifi_ap_record_t *ap = &aps->records[i];
            int size = snprintf(out + used, capacity - used, "%u: %.*s ch=%u rssi=%d\n", i, 32, ap->ssid, ap->primary, ap->rssi);
            if (size < 0 || (size_t)size >= capacity-used) break;
            used += size;
        }
        if (err == ESP_OK) { attack_unlock(); return; }
    } else {
        uint8_t candidates[MAX_JOB_TARGETS]; unsigned count = 0;
        const wifictl_ap_records_t *aps = wifictl_get_ap_records();
        if (attack_is_running()) err = ESP_ERR_INVALID_STATE;
        else if (!strcmp(command, "all")) {
            unsigned order[64];
            for (unsigned i=0; i<aps->count; ++i) order[i]=i;
            for (unsigned i=1; i<aps->count; ++i) {
                unsigned key=order[i], j=i;
                while (j && aps->records[order[j-1]].rssi < aps->records[key].rssi) { order[j]=order[j-1]; --j; }
                order[j]=key;
            }
            for (unsigned i=0; i<aps->count && count<MAX_JOB_TARGETS; ++i) candidates[count++]=order[i];
        } else {
            const char *p=command;
            while (err == ESP_OK && *p) {
                while (*p==' ') ++p;
                unsigned value; const char *end;
                if (!parse_number(p, 63, &value, &end) || value>=aps->count) { err=ESP_ERR_INVALID_ARG; break; }
                bool duplicate=false; for(unsigned i=0;i<count;++i) if(candidates[i]==value) duplicate=true;
                if (!duplicate) {
                    if(count==MAX_JOB_TARGETS) { err=ESP_ERR_INVALID_ARG; break; }
                    candidates[count++]=value;
                }
                p=end; while(*p==' ') ++p;
                if(!*p) break;
                if(*p++!=',' || !*p) { err=ESP_ERR_INVALID_ARG; break; }
            }
        }
        if (!count && err == ESP_OK) err=ESP_ERR_INVALID_ARG;
        if (err==ESP_OK) { memcpy(selected,candidates,count); selected_count=count; selection_scan=job->scan_generation; }
    }
    snprintf(out, capacity, "%s; selected=%u limit=%u s", err==ESP_OK?"accepted":esp_err_to_name(err), selected_count,duration);
    attack_unlock();
}
