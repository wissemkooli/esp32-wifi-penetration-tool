#include "webserver.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "wifi_controller.h"
#include "attack.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"
#include "page_index.h"
#include "web_assets.h"
#include "cJSON.h"
#include <stdlib.h>
#include <math.h>
#include "esp_timer.h"
#include <stdio.h>
#include <string.h>

static esp_err_t error_response(httpd_req_t *req, const char *status, const char *message) {
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    return httpd_resp_send(req, message, HTTPD_RESP_USE_STRLEN);
}
static esp_err_t root_get(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    return httpd_resp_send(req, (const char *)page_index, page_index_len);
}
static esp_err_t reset_head(httpd_req_t *req) {
    esp_err_t err = attack_reset_request();
    if (err == ESP_ERR_INVALID_STATE) return error_response(req, "409 Conflict", "A run is active");
    if (err != ESP_OK) return error_response(req, "503 Service Unavailable", "Please retry");
    httpd_resp_set_status(req, "202 Accepted");
    return httpd_resp_send(req, NULL, 0);
}
static esp_err_t run_post(httpd_req_t *req) {
    uint8_t request[4] = {0};
    if (req->content_len != sizeof(request))
        return error_response(req, "400 Bad Request", "Expected four configuration bytes");
    size_t received = 0;
    while (received < sizeof(request)) {
        int count = httpd_req_recv(req, (char *)request + received, sizeof(request) - received);
        if (count == HTTPD_SOCK_ERR_TIMEOUT)
            return error_response(req, "408 Request Timeout", "Incomplete request");
        if (count <= 0) return ESP_FAIL;
        received += count;
    }
    esp_err_t err = attack_submit(request[0], request[1], request[2], request[3]);
    if (err == ESP_ERR_INVALID_ARG)
        return error_response(req, "400 Bad Request", "Invalid AP, type, method or timeout");
    if (err == ESP_ERR_INVALID_STATE)
        return error_response(req, "409 Conflict", "Finish and reset the previous run first");
    if (err != ESP_OK) return error_response(req, "503 Service Unavailable", "Please retry");
    httpd_resp_set_status(req, "202 Accepted");
    return httpd_resp_send(req, NULL, 0);
}
static esp_err_t status_get(httpd_req_t *req) {
    attack_lock();
    const attack_status_t *status = attack_get_status();
    uint16_t size = status->state == FINISHED || status->state == TIMEOUT ? status->content_size : 0;
    uint8_t header[] = {status->state, status->type, size & 0xff, size >> 8};
    httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_send_chunk(req, (const char *)header, sizeof(header));
    if (err == ESP_OK && size) err = httpd_resp_send_chunk(req, status->content, size);
    if (err == ESP_OK) err = httpd_resp_send_chunk(req, NULL, 0);
    attack_unlock();
    return err;
}
static esp_err_t download_get(httpd_req_t *req) {
    attack_lock();
    const attack_status_t *status = attack_get_status();
    esp_err_t err;
    if (status->state == RUNNING) {
        err = error_response(req, "409 Conflict", "Capture is still running");
    } else if (status->type != ATTACK_TYPE_HANDSHAKE) {
        err = error_response(req, "404 Not Found", "No handshake capture available");
    } else {
        bool pcap = req->user_ctx != NULL;
        const void *buffer = pcap ? (const void *)pcap_serializer_get_buffer() :
                                    (const void *)hccapx_serializer_get();
        size_t size = pcap ? pcap_serializer_get_size() : sizeof(hccapx_t);
        if (!buffer || (pcap && size <= sizeof(pcap_global_header_t))) {
            err = error_response(req, "404 Not Found", "No valid capture available in this format");
        } else {
            httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
            httpd_resp_set_hdr(req, "Cache-Control", "no-store");
            httpd_resp_set_hdr(req, "Content-Disposition", pcap ?
                "attachment; filename=capture.pcap" : "attachment; filename=capture.hccapx");
            err = httpd_resp_send(req, buffer, size);
        }
    }
    attack_unlock();
    return err;
}
static void hex_string(char *out, const uint8_t *bytes, size_t size) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    out[size * 2] = 0;
}
static esp_err_t scan_get(httpd_req_t *req) {
    attack_lock();
    esp_err_t err;
    if (attack_get_status()->state == RUNNING) {
        err = error_response(req, "409 Conflict", "A run is active");
        goto done;
    }
    if (attack_legacy_scan() != ESP_OK) {
        err = error_response(req, "503 Service Unavailable", "Wi-Fi scan failed; please retry");
        goto done;
    }
    const wifictl_ap_records_t *aps = wifictl_get_ap_records();
    bool report = req->user_ctx != NULL;
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_type(req, report ? "application/json" : HTTPD_TYPE_OCTET);
    err = report ? httpd_resp_send_chunk(req, "{\"band\":\"2.4 GHz\",\"networks\":[", HTTPD_RESP_USE_STRLEN) : ESP_OK;
    for (unsigned i = 0; err == ESP_OK && i < aps->count; ++i) {
        const wifi_ap_record_t *ap = &aps->records[i];
        if (report) {
            char ssid[65], bssid[13], chunk[384];
            hex_string(ssid, ap->ssid, strnlen((const char *)ap->ssid, 32));
            hex_string(bssid, ap->bssid, 6);
            int size = snprintf(chunk, sizeof(chunk),
                "%s{\"id\":%u,\"ssid_hex\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"channel\":%u,"
                "\"security\":\"%s\",\"pmf\":\"%s\"}", i ? "," : "", i, ssid, bssid,
                ap->rssi, ap->primary, wifictl_auth_name(ap->authmode), security_pmf_name(wifictl_get_ap_pmf(i)));
            if (size < 0 || (size_t)size >= sizeof(chunk)) { err = ESP_FAIL; break; }
            err = httpd_resp_send_chunk(req, chunk, size);
        } else {
            char chunk[40];
            memcpy(chunk, ap->ssid, 33);
            memcpy(chunk + 33, ap->bssid, 6);
            chunk[39] = ap->rssi;
            err = httpd_resp_send_chunk(req, chunk, sizeof(chunk));
        }
    }
    if (report && err == ESP_OK) err = httpd_resp_send_chunk(req, "]}", 2);
    if (err == ESP_OK) err = httpd_resp_send_chunk(req, NULL, 0);
done:
    attack_unlock();
    return err;
}

static esp_err_t json_response(httpd_req_t *req, cJSON *value) {
    if (!value) return error_response(req, "503 Service Unavailable", "Out of memory");
    char *text = cJSON_PrintUnformatted(value); cJSON_Delete(value);
    if (!text) return error_response(req, "503 Service Unavailable", "Out of memory");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_send(req, text, HTTPD_RESP_USE_STRLEN); free(text); return err;
}
static cJSON *read_json(httpd_req_t *req) {
    if (!req->content_len || req->content_len > 1024) return NULL;
    char body[1025]; size_t offset = 0;
    while (offset < req->content_len) {
        int size = httpd_req_recv(req, body + offset, req->content_len - offset);
        if (size <= 0) return NULL;
        offset += size;
    }
    body[offset] = 0;
    const char *end = NULL;
    cJSON *value = cJSON_ParseWithLengthOpts(body, offset + 1, &end, true);
    if (!cJSON_IsObject(value)) { cJSON_Delete(value); return NULL; }
    return value;
}
static bool json_uint(cJSON *object, const char *key, uint32_t max, uint32_t *out) {
    cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsNumber(value) || !isfinite(value->valuedouble) || value->valuedouble < 0 ||
        value->valuedouble > max || floor(value->valuedouble) != value->valuedouble) return false;
    *out = value->valuedouble; return true;
}
static const char *job_state(void) {
    const attack_job_t *job = attack_get_job();
    if (job->scanning) return "scanning";
    if (job->stopping) return "stopping";
    if (attack_get_status()->state == RUNNING) return "running";
    if (attack_get_status()->state == READY) return "idle";
    return job->radio_error || !strcmp(job->reason, "setup_failed") || !strncmp(job->reason, "ESP_", 4) ? "error" : "complete";
}
static cJSON *job_json(void) {
    const attack_job_t *job = attack_get_job();
    cJSON *object = cJSON_CreateObject(); if (!object) return NULL;
    cJSON_AddNumberToObject(object, "schema_version", 1);
    cJSON_AddStringToObject(object, "boot_id", job->boot_id);
    cJSON_AddNumberToObject(object, "id", job->id);
    cJSON_AddNumberToObject(object, "scan_generation", job->scan_generation);
    cJSON_AddStringToObject(object, "state", job_state());
    cJSON_AddStringToObject(object, "reason", job->reason);
    cJSON_AddNumberToObject(object, "type", job->type);
    cJSON_AddNumberToObject(object, "method", job->method);
    cJSON_AddNumberToObject(object, "timeout", job->timeout);
    cJSON_AddNumberToObject(object, "elapsed", (job->started_us ?
        ((job->ended_us ? job->ended_us : esp_timer_get_time()) - job->started_us) / 1000000.0 : 0));
    cJSON_AddNumberToObject(object, "sent", job->sent); cJSON_AddNumberToObject(object, "tx_errors", job->tx_errors);
    cJSON_AddNumberToObject(object, "channel_errors", job->channel_errors);
    cJSON_AddNumberToObject(object, "radio_error_code", job->radio_error);
    cJSON_AddStringToObject(object, "radio_error_name", job->radio_error ? esp_err_to_name(job->radio_error) : "");
    cJSON_AddStringToObject(object, "radio_error_stage", job->radio_stage);
    cJSON_AddNumberToObject(object, "current_target", job->current_target);
    if (job->count) {
        char ssid[65], bssid[13]; hex_string(ssid, job->ssid, job->ssid_len);
        hex_string(bssid, job->targets[0].bssid, 6);
        cJSON_AddStringToObject(object, "ssid_hex", ssid); cJSON_AddStringToObject(object, "bssid", bssid);
        cJSON_AddNumberToObject(object, "channel", job->targets[0].primary);
        cJSON_AddStringToObject(object, "security", wifictl_auth_name(job->targets[0].authmode));
        cJSON_AddStringToObject(object, "pmf", security_pmf_name(job->pmf));
        cJSON *targets = cJSON_AddArrayToObject(object, "targets");
        for (unsigned i = 0; i < job->count; ++i) {
            hex_string(bssid, job->targets[i].bssid, 6); cJSON_AddItemToArray(targets, cJSON_CreateString(bssid));
        }
    }
    bool available = !attack_is_running() && job->count && job->type == ATTACK_TYPE_HANDSHAKE;
    cJSON_AddBoolToObject(object, "pcap", available && pcap_serializer_get_size() > sizeof(pcap_global_header_t));
    cJSON_AddBoolToObject(object, "hccapx", available && hccapx_serializer_get());
    if (!attack_is_running() && job->count && job->type == ATTACK_TYPE_PMKID) {
        cJSON *result = cJSON_AddArrayToObject(object, "pmkids");
        const attack_status_t *status = attack_get_status();
        if (status->content && status->content_size >= 13) {
            const uint8_t *bytes = (const uint8_t *)status->content;
            size_t offset = 13 + bytes[12]; char station[13], ap[13];
            hex_string(station, bytes, 6); hex_string(ap, bytes + 6, 6);
            cJSON_AddStringToObject(object, "station", station);
            cJSON_AddStringToObject(object, "pmkid_bssid", ap);
            for (; offset + 16 <= status->content_size; offset += 16) {
                char pmkid[33]; hex_string(pmkid, bytes + offset, 16); cJSON_AddItemToArray(result, cJSON_CreateString(pmkid));
            }
        }
    }
    return object;
}
static esp_err_t job_get(httpd_req_t *req) {
    attack_lock(); cJSON *value = job_json(); attack_unlock(); return json_response(req, value);
}
static esp_err_t device_get(httpd_req_t *req) {
    cJSON *value = cJSON_CreateObject();
    cJSON_AddNumberToObject(value, "schema_version", 1);
    cJSON_AddStringToObject(value, "firmware", "unified-1.0.1");
    cJSON_AddStringToObject(value, "idf_version", "v5.5.5");
    cJSON_AddStringToObject(value, "chip", "esp32"); cJSON_AddStringToObject(value, "band", "2.4 GHz");
    cJSON_AddNumberToObject(value, "max_targets", MAX_JOB_TARGETS);
    cJSON_AddStringToObject(value, "management_ssid", CONFIG_MGMT_AP_SSID);
    attack_lock(); cJSON_AddStringToObject(value, "boot_id", attack_get_job()->boot_id); attack_unlock();
    return json_response(req, value);
}
static esp_err_t api_error(httpd_req_t *req, esp_err_t err) {
    if (err == ESP_ERR_INVALID_STATE) return error_response(req, "409 Conflict", "Radio busy or scan selection is stale");
    if (err == ESP_ERR_INVALID_ARG) return error_response(req, "400 Bad Request", "Invalid job configuration");
    if (err == ESP_ERR_NOT_FOUND) return error_response(req, "404 Not Found", "Job belongs to another session or is no longer available");
    return error_response(req, "503 Service Unavailable", "Operation could not be queued; retry");
}
static esp_err_t job_post(httpd_req_t *req) {
    cJSON *body = read_json(req); if (!body) return api_error(req, ESP_ERR_INVALID_ARG);
    uint32_t type, method, timeout, scan;
    cJSON *targets = cJSON_GetObjectItemCaseSensitive(body, "targets");
    uint8_t indices[MAX_JOB_TARGETS]; unsigned count = cJSON_GetArraySize(targets);
    bool valid = json_uint(body, "type", 4, &type) && json_uint(body, "method", 2, &method) &&
        json_uint(body, "timeout", 255, &timeout) && json_uint(body, "scan_generation", UINT32_MAX, &scan) &&
        cJSON_IsArray(targets) && count > 0 && count <= MAX_JOB_TARGETS;
    for (unsigned i = 0; valid && i < count; ++i) {
        cJSON *target = cJSON_GetArrayItem(targets, i);
        valid = cJSON_IsNumber(target) && target->valuedouble >= 0 && target->valuedouble <= 63 &&
            floor(target->valuedouble) == target->valuedouble;
        if (valid) indices[i] = target->valuedouble;
    }
    attack_lock();
    cJSON *boot = cJSON_GetObjectItemCaseSensitive(body, "boot_id");
    esp_err_t err = !valid ? ESP_ERR_INVALID_ARG : !cJSON_IsString(boot) || strcmp(boot->valuestring, attack_get_job()->boot_id) ?
        ESP_ERR_NOT_FOUND : attack_submit_job(indices, count, type, method, timeout, scan);
    cJSON *value = err == ESP_OK ? job_json() : NULL;
    attack_unlock(); cJSON_Delete(body);
    if (err != ESP_OK) return api_error(req, err);
    httpd_resp_set_status(req, "202 Accepted"); return json_response(req, value);
}
static esp_err_t scan_post(httpd_req_t *req) {
    attack_lock(); esp_err_t err = attack_scan_submit(); cJSON *value = err == ESP_OK ? job_json() : NULL; attack_unlock();
    if (err != ESP_OK) return api_error(req, err);
    httpd_resp_set_status(req, "202 Accepted"); return json_response(req, value);
}
static esp_err_t stop_post(httpd_req_t *req) {
    cJSON *body = read_json(req); uint32_t id;
    cJSON *boot = cJSON_GetObjectItemCaseSensitive(body, "boot_id");
    esp_err_t err = cJSON_IsString(boot) && json_uint(body, "id", UINT32_MAX, &id) ?
        attack_stop_request(boot->valuestring, id) : ESP_ERR_INVALID_ARG;
    cJSON_Delete(body);
    if (err != ESP_OK) return api_error(req, err);
    return job_get(req);
}
static esp_err_t networks_get(httpd_req_t *req) {
    attack_lock();
    if (attack_get_job()->scanning) { attack_unlock(); return api_error(req, ESP_ERR_INVALID_STATE); }
    cJSON *value = cJSON_CreateObject(), *networks = cJSON_AddArrayToObject(value, "networks");
    cJSON_AddNumberToObject(value, "schema_version", 1);
    cJSON_AddNumberToObject(value, "scan_generation", attack_get_job()->scan_generation);
    const wifictl_ap_records_t *aps = wifictl_get_ap_records();
    for (unsigned i = 0; i < aps->count; ++i) {
        const wifi_ap_record_t *ap = &aps->records[i]; uint8_t bytes[32]; char ssid[65], bssid[13];
        unsigned size = wifictl_get_ap_ssid(i, bytes); hex_string(ssid, bytes, size);
        hex_string(bssid, ap->bssid, 6); cJSON *network = cJSON_CreateObject(); cJSON_AddItemToArray(networks, network);
        cJSON_AddNumberToObject(network, "id", i); cJSON_AddStringToObject(network, "ssid_hex", ssid);
        cJSON_AddStringToObject(network, "bssid", bssid); cJSON_AddNumberToObject(network, "rssi", ap->rssi);
        cJSON_AddNumberToObject(network, "channel", ap->primary);
        cJSON_AddStringToObject(network, "security", wifictl_auth_name(ap->authmode));
        cJSON_AddStringToObject(network, "pmf", security_pmf_name(wifictl_get_ap_pmf(i)));
    }
    attack_unlock(); return json_response(req, value);
}
/* Capture identity is checked under the same lock that protects the payload. */
static esp_err_t capture_get(httpd_req_t *req) {
    char query[96], boot[17], number[12];
    uint32_t id; char *end;
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "boot_id", boot, sizeof(boot)) != ESP_OK ||
        httpd_query_key_value(query, "id", number, sizeof(number)) != ESP_OK || !number[0])
        return api_error(req, ESP_ERR_INVALID_ARG);
    for (char *p = number; *p; ++p) if (*p < '0' || *p > '9') return api_error(req, ESP_ERR_INVALID_ARG);
    unsigned long long parsed = strtoull(number, &end, 10);
    if (*end || parsed > UINT32_MAX) return api_error(req, ESP_ERR_INVALID_ARG);
    id = parsed;
    attack_lock();
    const attack_job_t *job = attack_get_job();
    esp_err_t err = strcmp(boot, job->boot_id) || id != job->id || !job->count ?
        api_error(req, ESP_ERR_NOT_FOUND) : req->user_ctx == (void *)2 ? job_get(req) : download_get(req);
    attack_unlock(); return err;
}
static esp_err_t asset_get(httpd_req_t *req) {
    const web_asset_t *asset = req->user_ctx;
    httpd_resp_set_type(req, asset->mime); httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    return httpd_resp_send(req, (const char *)asset->data, asset->size);
}

void webserver_run(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 24;
    config.stack_size = 8192;
    httpd_handle_t server = NULL;
    ESP_ERROR_CHECK(httpd_start(&server, &config));
    const httpd_uri_t routes[] = {
        {.uri = "/", .method = HTTP_GET, .handler = root_get},
        {.uri = "/reset", .method = HTTP_HEAD, .handler = reset_head},
        {.uri = "/run-attack", .method = HTTP_POST, .handler = run_post},
        {.uri = "/status", .method = HTTP_GET, .handler = status_get},
        {.uri = "/capture.pcap", .method = HTTP_GET, .handler = download_get, .user_ctx = (void *)1},
        {.uri = "/capture.hccapx", .method = HTTP_GET, .handler = download_get},
        {.uri = "/ap-list", .method = HTTP_GET, .handler = scan_get},
        {.uri = "/security-report", .method = HTTP_GET, .handler = scan_get, .user_ctx = (void *)1},
        {.uri = "/api/v1/device", .method = HTTP_GET, .handler = device_get},
        {.uri = "/api/v1/networks", .method = HTTP_GET, .handler = networks_get},
        {.uri = "/api/v1/scan", .method = HTTP_POST, .handler = scan_post},
        {.uri = "/api/v1/job", .method = HTTP_GET, .handler = job_get},
        {.uri = "/api/v1/jobs", .method = HTTP_POST, .handler = job_post},
        {.uri = "/api/v1/stop", .method = HTTP_POST, .handler = stop_post},
        {.uri = "/api/v1/capture", .method = HTTP_GET, .handler = capture_get, .user_ctx = (void *)2},
        {.uri = "/api/v1/capture.pcap", .method = HTTP_GET, .handler = capture_get, .user_ctx = (void *)1},
        {.uri = "/api/v1/capture.hccapx", .method = HTTP_GET, .handler = capture_get}
    };
    for (unsigned i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i)
        ESP_ERROR_CHECK(httpd_register_uri_handler(server, &routes[i]));
    for (unsigned i = 0; i < WEB_ASSET_COUNT; ++i) {
        httpd_uri_t route = {.uri = web_assets[i].path, .method = HTTP_GET, .handler = asset_get, .user_ctx = (void *)&web_assets[i]};
        ESP_ERROR_CHECK(httpd_register_uri_handler(server, &route));
    }
}
