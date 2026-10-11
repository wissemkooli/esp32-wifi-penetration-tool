/** Common lifecycle. All start/stop operations run on the default event loop. */
#include "attack.h"
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "attack_pmkid.h"
#include "attack_handshake.h"
#include "attack_dos.h"
#include "wifi_controller.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"
#include "controller.h"
#include "esp_random.h"
#include <stdio.h>

static const char *TAG = "attack";
static attack_status_t attack_status = {.state = READY, .type = UINT8_MAX};
static esp_timer_handle_t attack_timeout_handle;
static SemaphoreHandle_t status_mutex;
static int64_t deadline_us;
static wifi_ap_record_t active_ap;
static attack_job_t job;
ESP_EVENT_DEFINE_BASE(ATTACK_EVENTS);
enum { START_REQUEST, RESET_REQUEST, TIMEOUT_REQUEST, STOP_REQUEST, SCAN_REQUEST, CONTROLLER_FAILURE };
typedef struct {
    uint8_t type, method, timeout;
    wifi_ap_record_t ap;
} start_request_t;

void attack_lock(void) { xSemaphoreTakeRecursive(status_mutex, portMAX_DELAY); }
void attack_unlock(void) { xSemaphoreGiveRecursive(status_mutex); }
const attack_status_t *attack_get_status(void) { return &attack_status; }
const attack_job_t *attack_get_job(void) { return &job; }
void attack_set_error(const char *reason) {
    attack_lock(); snprintf(job.reason, sizeof(job.reason), "%s", reason); attack_unlock();
}
void attack_note_tx(bool success, unsigned target) {
    attack_lock();
    if (success) ++job.sent; else ++job.tx_errors;
    job.current_target = target;
    attack_unlock();
}

void attack_controller_diagnostics(uint32_t id, uint32_t ok, uint32_t failed,
                                   bool registered, esp_err_t callback_error) {
    attack_lock();
    if (job.id == id && job.type == ATTACK_TYPE_CONTROLLER) {
        job.tx_done_ok = ok; job.tx_done_fail = failed;
        job.tx_callback_registered = registered; job.tx_callback_error = callback_error;
    }
    attack_unlock();
}

esp_err_t attack_controller_failure_request(uint32_t id, esp_err_t error,
                                           const char *stage, unsigned target) {
    if (error == ESP_OK || !stage || target >= MAX_JOB_TARGETS) return ESP_ERR_INVALID_ARG;
    attack_lock();
    if (job.id != id || attack_status.state != RUNNING || job.type != ATTACK_TYPE_CONTROLLER) {
        attack_unlock(); return ESP_ERR_INVALID_STATE;
    }
    /* Preserve the first cause. Queue retries must not count the same failure twice. */
    if (!job.radio_error) {
        job.radio_error = error; job.current_target = target;
        snprintf(job.radio_stage, sizeof(job.radio_stage), "%s", stage);
        if (!strncmp(stage, "channel", 7)) ++job.channel_errors;
        else if (!strcmp(stage, "transmit")) ++job.tx_errors;
        snprintf(job.reason, sizeof(job.reason), "radio_failure");
    }
    esp_err_t err = esp_event_post(ATTACK_EVENTS, CONTROLLER_FAILURE, &id, sizeof(id), 0);
    attack_unlock(); return err;
}

bool attack_is_running(void) {
    attack_lock();
    bool running = attack_status.state == RUNNING;
    attack_unlock();
    return running;
}

void attack_update_status(attack_state_t state) {
    if (state != RUNNING) {
        esp_err_t err = esp_timer_stop(attack_timeout_handle);
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
            ESP_LOGW(TAG, "Timer stop failed: %s", esp_err_to_name(err));
        wifictl_sniffer_stop();
        wifictl_sta_disconnect();
        wifictl_restore_ap_mac();
        wifictl_mgmt_ap_start();
    }
    attack_lock();
    attack_status.state = state;
    if (state != RUNNING) {
        job.ended_us = esp_timer_get_time();
        job.scanning = job.stopping = false;
        if (!job.reason[0]) snprintf(job.reason, sizeof(job.reason), "%s", state == FINISHED ? "complete" : "setup_failed");
    }
    attack_unlock();
}

void attack_append_status_content(uint8_t *buffer, unsigned size) {
    attack_lock();
    if (!buffer || !size || size > (unsigned)UINT16_MAX - attack_status.content_size) {
        ESP_LOGW(TAG, "Status buffer limit reached or invalid input");
        attack_unlock();
        return;
    }
    char *content = realloc(attack_status.content, attack_status.content_size + size);
    if (content) {
        memcpy(content + attack_status.content_size, buffer, size);
        attack_status.content = content;
        attack_status.content_size += size;
    } else ESP_LOGE(TAG, "Out of memory appending status");
    attack_unlock();
}

char *attack_alloc_result_content(unsigned size) {
    if (!size || size > UINT16_MAX) return NULL;
    char *content = malloc(size);
    if (!content) return NULL;
    attack_lock();
    free(attack_status.content);
    attack_status.content = content;
    attack_status.content_size = size;
    attack_unlock();
    return content;
}

/* Timer callbacks must not wait for the event loop while it is stopping timers. */
static void attack_timeout(void *arg) {
    if (esp_event_post(ATTACK_EVENTS, TIMEOUT_REQUEST, NULL, 0, 0) != ESP_OK)
        esp_timer_start_once(attack_timeout_handle, 10000);
}

static void stop_producers(void) {
    switch (attack_status.type) {
        case ATTACK_TYPE_PMKID: attack_pmkid_stop(); break;
        case ATTACK_TYPE_HANDSHAKE: attack_handshake_stop(); break;
        case ATTACK_TYPE_DOS: attack_dos_stop(); break;
        case ATTACK_TYPE_CONTROLLER: controller_stop(); break;
        default: break;
    }
}
static void attack_timeout_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (!attack_is_running() || job.scanning || esp_timer_get_time() < deadline_us) return;
    stop_producers();
    if (!job.radio_error) attack_set_error("deadline");
    /* Results become readable only after all producers have stopped. */
    attack_update_status(TIMEOUT);
}

static void clear_results(void) {
    free(attack_status.content); attack_status.content = NULL; attack_status.content_size = 0;
    pcap_serializer_deinit(); hccapx_serializer_init(NULL, 0);
}

/* Reserve and copy every target while holding the same lock used by scans. */
static esp_err_t submit(const uint8_t *indices, unsigned count, uint8_t type,
                        uint8_t method, uint8_t timeout, uint32_t scan, bool replace) {
    if (!indices || !timeout || !count || count > MAX_JOB_TARGETS || type < 1 || type > ATTACK_TYPE_CONTROLLER ||
        (type != ATTACK_TYPE_CONTROLLER && count != 1) ||
        (type == ATTACK_TYPE_PMKID || type == ATTACK_TYPE_CONTROLLER ? method != 0 : method > 2))
        return ESP_ERR_INVALID_ARG;
    attack_lock();
    if (attack_status.state == RUNNING || (!replace && attack_status.state != READY) || scan != job.scan_generation) {
        attack_unlock(); return ESP_ERR_INVALID_STATE;
    }
    attack_job_t next = {.id = job.id + 1, .scan_generation = job.scan_generation,
        .type = type, .method = method, .timeout = timeout, .count = count};
    memcpy(next.boot_id, job.boot_id, sizeof(next.boot_id));
    for (unsigned i = 0; i < count; ++i) {
        const wifi_ap_record_t *ap = wifictl_get_ap_record(indices[i]);
        if (!ap || !ap->primary || ap->primary > 14) { attack_unlock(); return ESP_ERR_INVALID_ARG; }
        for (unsigned j = 0; j < i; ++j)
            if (!memcmp(next.targets[j].bssid, ap->bssid, 6)) { attack_unlock(); return ESP_ERR_INVALID_ARG; }
        next.targets[i] = *ap;
    }
    next.pmf = wifictl_get_ap_pmf(indices[0]);
    next.ssid_len = wifictl_get_ap_ssid(indices[0], next.ssid);
    start_request_t request = {.type = type, .method = method, .timeout = timeout, .ap = next.targets[0]};
    esp_err_t err = esp_event_post(ATTACK_EVENTS, START_REQUEST, &request, sizeof(request), 0);
    if (err == ESP_OK) {
        clear_results(); job = next;
        attack_status.state = RUNNING; attack_status.type = type;
    }
    attack_unlock(); return err;
}
esp_err_t attack_submit_job(const uint8_t *indices, unsigned count, uint8_t type,
                           uint8_t method, uint8_t timeout, uint32_t scan) {
    return submit(indices, count, type, method, timeout, scan, true);
}

esp_err_t attack_submit(uint8_t ap_index, uint8_t type, uint8_t method, uint8_t timeout) {
    if (type > ATTACK_TYPE_DOS) return ESP_ERR_INVALID_ARG;
    attack_lock();
    esp_err_t err = submit(&ap_index, 1, type, method, timeout, job.scan_generation, false);
    attack_unlock(); return err;
}

static void attack_request_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    start_request_t *request = data;
    attack_lock();
    job.started_us = esp_timer_get_time();
    attack_unlock();
    active_ap = request->ap;
    attack_config_t config = {.type = request->type, .method = request->method,
                             .timeout = request->timeout, .ap_record = &active_ap};
    deadline_us = esp_timer_get_time() + (int64_t)config.timeout * 1000000;
    esp_err_t err = esp_timer_start_once(attack_timeout_handle, (uint64_t)config.timeout * 1000000);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cannot start timeout: %s", esp_err_to_name(err));
        attack_update_status(TIMEOUT);
        return;
    }
    switch (config.type) {
        case ATTACK_TYPE_PMKID: attack_pmkid_start(&config); break;
        case ATTACK_TYPE_HANDSHAKE: attack_handshake_start(&config); break;
        case ATTACK_TYPE_DOS: attack_dos_start(&config); break;
        case ATTACK_TYPE_CONTROLLER:
            err = controller_start(job.targets, job.count);
            if (err != ESP_OK) {
                controller_stop();
                if (!job.radio_error) attack_set_error(esp_err_to_name(err));
                attack_update_status(TIMEOUT);
            }
            break;
        default: attack_update_status(TIMEOUT); break;
    }
}

static void scan_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    attack_lock(); job.started_us = esp_timer_get_time(); attack_unlock();
    esp_err_t err = wifictl_scan_nearby_aps();
    attack_lock(); ++job.scan_generation; attack_unlock();
    attack_set_error(err == ESP_OK ? "scan_complete" : esp_err_to_name(err));
    attack_update_status(err == ESP_OK ? FINISHED : TIMEOUT);
}
esp_err_t attack_scan_submit(void) {
    attack_lock();
    if (attack_status.state == RUNNING) { attack_unlock(); return ESP_ERR_INVALID_STATE; }
    esp_err_t err = esp_event_post(ATTACK_EVENTS, SCAN_REQUEST, NULL, 0, 0);
    if (err == ESP_OK) {
        ++job.id; job.type = 0; job.count = 0; job.scanning = true; job.reason[0] = 0;
        job.started_us = job.ended_us = 0; job.sent = job.tx_errors = job.channel_errors = 0;
        job.radio_error = ESP_OK; job.radio_stage[0] = 0;
        job.tx_done_ok = job.tx_done_fail = 0;
        job.tx_callback_registered = false; job.tx_callback_error = ESP_OK;
        attack_status.state = RUNNING; attack_status.type = 0;
    }
    attack_unlock(); return err;
}
esp_err_t attack_legacy_scan(void) {
    attack_lock();
    if (attack_is_running()) { attack_unlock(); return ESP_ERR_INVALID_STATE; }
    esp_err_t err = wifictl_scan_nearby_aps(); ++job.scan_generation;
    wifictl_mgmt_ap_start(); attack_unlock(); return err;
}
static void stop_handler(void *arg, esp_event_base_t base, int32_t event_id, void *data) {
    uint32_t id = *(uint32_t *)data;
    if (!attack_is_running() || job.id != id || job.scanning) return;
    stop_producers();
    if (!job.radio_error) attack_set_error("cancelled");
    attack_update_status(TIMEOUT);
}
static void controller_failure_handler(void *arg, esp_event_base_t base, int32_t event_id, void *data) {
    uint32_t id = *(uint32_t *)data;
    if (!attack_is_running() || job.id != id || job.type != ATTACK_TYPE_CONTROLLER) return;
    stop_producers(); attack_update_status(TIMEOUT);
}
esp_err_t attack_stop_request(const char *boot, uint32_t id) {
    attack_lock();
    if (!boot || strcmp(boot, job.boot_id) || id != job.id) { attack_unlock(); return ESP_ERR_NOT_FOUND; }
    if (!attack_is_running() || job.scanning) { attack_unlock(); return ESP_ERR_INVALID_STATE; }
    esp_err_t err = esp_event_post(ATTACK_EVENTS, STOP_REQUEST, &id, sizeof(id), 0);
    if (err == ESP_OK) job.stopping = true;
    attack_unlock(); return err;
}

esp_err_t attack_reset_request(void) {
    attack_lock();
    esp_err_t err = attack_status.state == RUNNING ? ESP_ERR_INVALID_STATE :
        esp_event_post(ATTACK_EVENTS, RESET_REQUEST, NULL, 0, 0);
    attack_unlock();
    return err;
}

static void attack_reset_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    attack_lock();
    if (attack_status.state != RUNNING) {
        clear_results();
        attack_status.type = UINT8_MAX;
        attack_status.state = READY;
        job.count = 0;
    }
    attack_unlock();
}

void attack_init(void) {
    status_mutex = xSemaphoreCreateRecursiveMutex();
    if (!status_mutex) ESP_ERROR_CHECK(ESP_ERR_NO_MEM);
    snprintf(job.boot_id, sizeof(job.boot_id), "%08lx%08lx", (unsigned long)esp_random(), (unsigned long)esp_random());
    const esp_timer_create_args_t timer_args = {.callback = attack_timeout, .name = "run-timeout"};
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &attack_timeout_handle));
    ESP_ERROR_CHECK(esp_event_handler_register(ATTACK_EVENTS, START_REQUEST, attack_request_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(ATTACK_EVENTS, RESET_REQUEST, attack_reset_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(ATTACK_EVENTS, TIMEOUT_REQUEST, attack_timeout_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(ATTACK_EVENTS, STOP_REQUEST, stop_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(ATTACK_EVENTS, SCAN_REQUEST, scan_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(ATTACK_EVENTS, CONTROLLER_FAILURE, controller_failure_handler, NULL));
}
