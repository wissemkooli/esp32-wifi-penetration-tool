#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "attack.h"
#include "attack_method.h"
#include "frame_analyzer.h"
#include "frame_analyzer_parser.h"
#include "hccapx_serializer.h"
#include "pcap_serializer.h"
#include "security_report.h"
#include "wifi_controller.h"
#include "esp_timer.h"
#include "controller.h"
#include "serial_console.h"
/* Include the HTTP translation unit to exercise its private handlers. */
#include "../components/webserver/webserver.c"

#ifdef _WIN32
#include <windows.h>
#endif

ESP_EVENT_DEFINE_BASE(SNIFFER_EVENTS);
static struct { esp_event_base_t base; int32_t id; esp_event_handler_t fn; void *arg; } handlers[16];
static struct { esp_event_base_t base; int32_t id; void *data; } queue[64];
static unsigned queued;
static bool fail_posts;
esp_err_t esp_event_handler_register(esp_event_base_t base, int32_t id, esp_event_handler_t fn, void *arg) {
    for (unsigned i = 0; i < 16; ++i) {
        if (!handlers[i].fn || (handlers[i].base == base && handlers[i].id == id && handlers[i].fn == fn)) {
            handlers[i].base = base; handlers[i].id = id; handlers[i].fn = fn; handlers[i].arg = arg;
            return ESP_OK;
        }
    }
    return ESP_ERR_NO_MEM;
}
esp_err_t esp_event_handler_unregister(esp_event_base_t base, int32_t id, esp_event_handler_t fn) {
    /* The original wildcard cleanup fails this test. */
    assert(base != ESP_EVENT_ANY_BASE && id != ESP_EVENT_ANY_ID);
    for (unsigned i = 0; i < 16; ++i) if (handlers[i].base == base && handlers[i].id == id && handlers[i].fn == fn) {
        handlers[i].fn = NULL; return ESP_OK;
    }
    return ESP_ERR_NOT_FOUND;
}
esp_err_t esp_event_post(esp_event_base_t base, int32_t id, const void *data, size_t size, unsigned timeout) {
    assert(timeout == 0);
    if (fail_posts || queued == 64) return ESP_ERR_TIMEOUT;
    queue[queued].base = base; queue[queued].id = id;
    queue[queued].data = size ? malloc(size) : NULL;
    if (size) memcpy(queue[queued].data, data, size);
    ++queued; return ESP_OK;
}
static void dispatch(void) {
    while (queued) {
        esp_event_base_t base = queue[0].base;
        int32_t id = queue[0].id;
        void *data = queue[0].data;
        memmove(queue, queue + 1, (--queued) * sizeof(queue[0]));
        for (unsigned i = 0; i < 16; ++i)
            if (handlers[i].fn && handlers[i].base == base && handlers[i].id == id)
                handlers[i].fn(handlers[i].arg, base, id, data);
        free(data);
    }
}
struct mock_timer { esp_timer_create_args_t args; bool armed; int64_t deadline; } timer;
static int64_t now;
esp_err_t esp_timer_create(const esp_timer_create_args_t *args, esp_timer_handle_t *out) {
    timer.args = *args; *out = &timer; return ESP_OK;
}
esp_err_t esp_timer_start_once(esp_timer_handle_t handle, uint64_t us) {
    if (handle->armed) return ESP_ERR_INVALID_STATE;
    handle->armed = true; handle->deadline = now + us; return ESP_OK;
}
esp_err_t esp_timer_stop(esp_timer_handle_t handle) {
    if (!handle->armed) return ESP_ERR_INVALID_STATE;
    handle->armed = false; return ESP_OK;
}
int64_t esp_timer_get_time(void) { return now; }
static void expire(void) { assert(timer.armed); now = timer.deadline; timer.armed = false; timer.args.callback(NULL); }
static wifictl_ap_records_t aps = {.count = 1, .records = {{.ssid = "test", .bssid = {2, 0, 0, 0, 0, 1}, .primary = 1}}};
static uint32_t generation;
static bool sniffing, controlling;
static unsigned restored;
static bool fail_sniffer, fail_connection, fail_method;
const wifi_ap_record_t *wifictl_get_ap_record(unsigned i) { return i < aps.count ? &aps.records[i] : NULL; }
const wifictl_ap_records_t *wifictl_get_ap_records(void) { return &aps; }
esp_err_t wifictl_scan_nearby_aps(void) { return ESP_OK; }
pmf_status_t wifictl_get_ap_pmf(unsigned i) { (void)i; return PMF_REQUIRED; }
unsigned wifictl_get_ap_ssid(unsigned i, uint8_t out[32]) { unsigned size=strlen((char *)aps.records[i].ssid); memcpy(out,aps.records[i].ssid,size); return size; }
const char *wifictl_auth_name(int a) { (void)a; return "WPA3-Personal"; }
uint32_t wifictl_sniffer_generation(void) { return generation; }
esp_err_t wifictl_sniffer_start(uint8_t c) {
    assert(c == 1); if (fail_sniffer) return ESP_FAIL;
    ++generation; sniffing = true; return ESP_OK;
}
void wifictl_sniffer_stop(void) { sniffing = false; }
esp_err_t wifictl_sniffer_filter_frame_types(bool d, bool m, bool c) { (void)d; (void)m; (void)c; return ESP_OK; }
void wifictl_mgmt_ap_start(void) { ++restored; }
void wifictl_restore_ap_mac(void) {}
void wifictl_get_sta_mac(uint8_t *out) { memset(out, 3, 6); }
esp_err_t wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap, const char *pw) {
    (void)ap; (void)pw; return fail_connection ? ESP_FAIL : ESP_OK;
}
void wifictl_sta_disconnect(void) {}
esp_err_t attack_method_broadcast(const wifi_ap_record_t *ap, unsigned period) {
    (void)ap; (void)period; return fail_method ? ESP_FAIL : ESP_OK;
}
void attack_method_broadcast_stop(void) {}
esp_err_t attack_method_rogueap(const wifi_ap_record_t *ap) { (void)ap; return fail_method ? ESP_FAIL : ESP_OK; }
esp_err_t controller_start(const wifi_ap_record_t *targets, unsigned count) {
    assert(targets && count && count<=8); if(fail_method)return ESP_FAIL; controlling=true; return ESP_OK;
}
void controller_stop(void) { controlling=false; }

esp_err_t httpd_resp_set_status(httpd_req_t *r, const char *s) { r->status = s; return ESP_OK; }
esp_err_t httpd_resp_set_type(httpd_req_t *r, const char *s) { (void)r; (void)s; return ESP_OK; }
esp_err_t httpd_resp_set_hdr(httpd_req_t *r, const char *n, const char *v) { (void)r; (void)n; (void)v; return ESP_OK; }
esp_err_t httpd_resp_send_chunk(httpd_req_t *r, const char *data, int size) {
    if (size == HTTPD_RESP_USE_STRLEN) size = strlen(data);
    assert(size >= 0 && (size == 0 || data));
    r->response = realloc(r->response, r->response_size + size + 1);
    if (size) memcpy(r->response + r->response_size, data, size);
    r->response_size += size; r->response[r->response_size] = 0; return ESP_OK;
}
esp_err_t httpd_resp_send(httpd_req_t *r, const char *data, int size) { return httpd_resp_send_chunk(r, data, size); }
int httpd_req_recv(httpd_req_t *r, char *out, size_t size) {
    if (r->recv_error) return r->recv_error;
    if (r->chunk_limit && size > r->chunk_limit) size = r->chunk_limit;
    memcpy(out, r->body + r->position, size); r->position += size; return size;
}
esp_err_t httpd_start(httpd_handle_t *out, const httpd_config_t *cfg) { (void)cfg; static int value; *out = &value; return ESP_OK; }
esp_err_t httpd_register_uri_handler(httpd_handle_t h, const httpd_uri_t *r) { (void)h; (void)r; return ESP_OK; }
esp_err_t httpd_req_get_url_query_str(httpd_req_t *r, char *out, size_t capacity) {
    if(!r->query || strlen(r->query)>=capacity)return ESP_ERR_INVALID_ARG;
    strcpy(out,r->query); return ESP_OK;
}
esp_err_t httpd_query_key_value(const char *query, const char *key, char *out, size_t capacity) {
    size_t length=strlen(key);
    for(const char *p=query; p && *p; p=strchr(p,'&')) {
        if(*p=='&')++p;
        if(!strncmp(p,key,length) && p[length]=='=') {
            p+=length+1; const char *end=strchr(p,'&'); size_t size=end?(size_t)(end-p):strlen(p);
            if(size>=capacity)return ESP_ERR_INVALID_ARG;
            memcpy(out,p,size); out[size]=0; return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}
static void clear_response(httpd_req_t *r) { free(r->response); r->response = NULL; r->response_size = 0; r->status = NULL; }

static const uint8_t ap_mac[] = {2, 0, 0, 0, 0, 1};
static size_t make_frame(uint8_t *out, unsigned message, uint8_t sta_id, uint8_t replay) {
    memset(out, 0, 256);
    bool ap = message == 1 || message == 3;
    out[0] = 0x08; out[1] = ap ? 2 : 1;
    uint8_t sta[] = {4, 0, 0, 0, 0, sta_id};
    memcpy(out + 4, ap ? sta : ap_mac, 6);
    memcpy(out + 10, ap ? ap_mac : sta, 6);
    memcpy(out + 16, ap_mac, 6);
    uint8_t llc[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
    memcpy(out + 24, llc, 8);
    out[32] = 2; out[33] = 3; out[35] = 95;
    uint8_t *key = out + 36;
    key[0] = 2;
    unsigned info = message == 1 ? 0x008a : message == 2 ? 0x010a : message == 3 ? 0x13ca : 0x030a;
    key[1] = info >> 8; key[2] = info;
    key[12] = replay;
    if (message != 4) memset(key + 13, ap ? 0x11 : 0x22, 32);
    if (message != 1) memset(key + 77, 0x33, 16);
    return 131;
}

static void test_parser_bounds(void) {
    _Static_assert(sizeof(eapol_key_packet_t) == 95, "wire size");
    _Static_assert(sizeof(hccapx_t) == 393, "HCCAPX wire size");
    uint8_t frame[256]; size_t size = make_frame(frame, 1, 1, 1);
    for (size_t len = 0; len < size; ++len) {
#ifdef _WIN32
        SYSTEM_INFO info; GetSystemInfo(&info);
        uint8_t *pages = VirtualAlloc(NULL, info.dwPageSize * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        assert(pages); DWORD old;
        assert(VirtualProtect(pages + info.dwPageSize, info.dwPageSize, PAGE_NOACCESS, &old));
        uint8_t *short_frame = pages + info.dwPageSize - len;
        memcpy(short_frame, frame, len);
        assert(!parse_eapol_packet((data_frame_t *)short_frame, len));
        assert(VirtualFree(pages, 0, MEM_RELEASE));
#else
        uint8_t *short_frame = malloc(len ? len : 1);
        memcpy(short_frame, frame, len);
        assert(!parse_eapol_packet((data_frame_t *)short_frame, len));
        free(short_frame);
#endif
    }
    eapol_packet_t *packet = parse_eapol_packet((data_frame_t *)frame, size);
    assert(packet && parse_eapol_key_packet(packet, 99));
    frame[35] = 250; assert(!parse_eapol_packet((data_frame_t *)frame, size));
    make_frame(frame, 1, 1, 1); frame[129] = 1;
    packet = parse_eapol_packet((data_frame_t *)frame, size);
    assert(packet && !parse_eapol_key_packet(packet, 99));
    make_frame(frame, 1, 1, 1); frame[1] |= 0x40;
    assert(!parse_eapol_packet((data_frame_t *)frame, size));
    make_frame(frame, 1, 1, 1); frame[0] = 0x48;
    assert(!parse_eapol_packet((data_frame_t *)frame, size));
    puts("PASS: frame truncation, protected/null frames, nested lengths");
}

static void test_pmkid(void) {
    uint8_t bytes[95 + 44] = {0};
    eapol_key_packet_t *key = (void *)bytes;
    bytes[94] = 44;
    for (unsigned i = 0; i < 2; ++i) {
        uint8_t *element = bytes + 95 + i * 22;
        uint8_t selector[] = {221, 20, 0, 15, 172, 4}; memcpy(element, selector, 6);
        memset(element + 6, i + 1, 16);
    }
    pmkid_item_t *list = parse_pmkid(key, sizeof(bytes));
    assert(list && list->next && !list->next->next && list->pmkid[0] == 2 && list->next->pmkid[0] == 1);
    free_pmkid_list(list);
    for (size_t len = 0; len < sizeof(bytes); ++len) assert(!parse_pmkid(key, len));
    key->key_information.bytes[0] = 0x10; assert(!parse_pmkid(key, sizeof(bytes)));
    key->key_information.bytes[0] = 0; bytes[118] = 19; assert(!parse_pmkid(key, sizeof(bytes)));
    puts("PASS: PMKID element boundaries, encryption flag, malformed lengths");
}

static void test_handshakes(void) {
    uint8_t frame[256]; size_t size;
    hccapx_serializer_init((const uint8_t *)"one", 3);
    size = make_frame(frame, 1, 1, 1); hccapx_serializer_add_frame((void *)frame, size);
    size = make_frame(frame, 2, 1, 1); hccapx_serializer_add_frame((void *)frame, size);
    hccapx_t *result = hccapx_serializer_get();
    assert(result && result->message_pair == 0 && result->keyver == 2 && result->eapol[81] == 0);
    hccapx_serializer_init((const uint8_t *)"two", 3);
    assert(!hccapx_serializer_get());
    size = make_frame(frame, 2, 2, 4); hccapx_serializer_add_frame((void *)frame, size);
    size = make_frame(frame, 3, 2, 5); hccapx_serializer_add_frame((void *)frame, size);
    result = hccapx_serializer_get();
    assert(result && result->message_pair == 2 && result->nonce_ap[0] == 0x11 && result->mac_sta[5] == 2);
    size = make_frame(frame, 3, 2, 8); hccapx_serializer_add_frame((void *)frame, size);
    assert(!hccapx_serializer_get());
    hccapx_serializer_init((const uint8_t *)"two", 33); assert(!hccapx_serializer_get());
    puts("PASS: repeated runs, missed M1, replay mismatch, invalid SSID length");
}

static void test_security_report(void) {
    uint8_t frame[64] = {0x80}; memcpy(frame + 16, ap_mac, 6);
    uint8_t rsn[] = {48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,8,0xc0,0};
    memcpy(frame + 36, rsn, sizeof(rsn));
    security_observation_t info;
    assert(security_parse_advertisement(frame, 58, &info) && info.pmf == PMF_REQUIRED);
    frame[56] = 0x80; assert(security_parse_advertisement(frame, 58, &info) && info.pmf == PMF_CAPABLE);
    frame[56] = 0; assert(security_parse_advertisement(frame, 58, &info) && info.pmf == PMF_NOT_ADVERTISED);
    frame[56] = 0x40; assert(security_parse_advertisement(frame, 58, &info) && info.pmf == PMF_INCONSISTENT);
    for (unsigned len = 37; len < 58; ++len) assert(!security_parse_advertisement(frame, len, &info));
    frame[44] = 255; assert(!security_parse_advertisement(frame, 58, &info));
    assert(security_parse_advertisement(frame, 36, &info) && !info.rsn_seen);
    puts("PASS: PMF required/optional/absent/inconsistent, malformed RSN lists");
}

static void deliver_frame(unsigned message, uint32_t run) {
    uint8_t frame[256]; size_t size = make_frame(frame, message, 1, 1);
    size_t total = sizeof(sniffer_frame_t) + sizeof(wifi_promiscuous_pkt_t) + size + 4;
    sniffer_frame_t *event = calloc(1, total); event->generation = run;
    wifi_promiscuous_pkt_t *packet = (void *)event->packet;
    packet->rx_ctrl.sig_len = size + 4; memcpy(packet->payload, frame, size);
    assert(esp_event_post(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA, event, total, 0) == ESP_OK);
    free(event); dispatch();
}

static void test_lifecycle_and_http(void) {
    attack_init();
    assert(attack_submit(1, 1, 2, 5) == ESP_ERR_INVALID_ARG);
    assert(attack_submit(0, 1, 2, 0) == ESP_ERR_INVALID_ARG);
    assert(attack_submit(0, 0, 0, 5) == ESP_ERR_INVALID_ARG);
    assert(attack_submit(0, 1, 3, 5) == ESP_ERR_INVALID_ARG);
    fail_posts = true; assert(attack_submit(0, 1, 2, 5) == ESP_ERR_TIMEOUT); fail_posts = false;
    assert(attack_get_status()->state == READY);
    httpd_req_t req = {.content_len = 1};
    assert(run_post(&req) == ESP_OK && !strcmp(req.status, "400 Bad Request")); clear_response(&req);
    req.content_len = 4; req.recv_error = HTTPD_SOCK_ERR_TIMEOUT;
    assert(run_post(&req) == ESP_OK && !strcmp(req.status, "408 Request Timeout")); clear_response(&req);
    const char body[] = {0, 1, 2, 5}; req.body = body; req.recv_error = 0; req.chunk_limit = 1;
    assert(run_post(&req) == ESP_OK && !strcmp(req.status, "202 Accepted")); clear_response(&req);
    assert(attack_submit(0, 1, 2, 5) == ESP_ERR_INVALID_STATE);
    assert(attack_reset_request() == ESP_ERR_INVALID_STATE);
    dispatch(); assert(sniffing);
    deliver_frame(1, generation); deliver_frame(2, generation);
    assert(download_get(&req) == ESP_OK && !strcmp(req.status, "409 Conflict")); clear_response(&req);
    fail_posts = true; expire(); assert(timer.armed); fail_posts = false;
    expire(); assert(attack_is_running()); dispatch();
    assert(!sniffing && attack_get_status()->state == TIMEOUT && hccapx_serializer_get());
    assert(download_get(&req) == ESP_OK && req.response_size == sizeof(hccapx_t)); clear_response(&req);
    req.user_ctx = (void *)1;
    assert(download_get(&req) == ESP_OK && req.response_size > 24); clear_response(&req);
    assert(attack_reset_request() == ESP_OK); dispatch();
    assert(!pcap_serializer_get_buffer() && !hccapx_serializer_get());
    assert(attack_submit(0, 1, 2, 5) == ESP_OK); dispatch();
    deliver_frame(1, generation - 1); assert(attack_get_status()->content_size == 0);
    expire(); dispatch();
    assert(download_get(&req) == ESP_OK && !strcmp(req.status, "404 Not Found")); clear_response(&req);
    assert(attack_reset_request() == ESP_OK); dispatch();
    uint8_t *large = calloc(1, 65535); attack_append_status_content(large, 65535);
    attack_append_status_content(large, 1); assert(attack_get_status()->content_size == 65535); free(large);
    assert(attack_reset_request() == ESP_OK); dispatch();
    puts("PASS: partial HTTP reads, invalid inputs, run reservation, stop/reset, stale frames, queue-full timeout retry, safe downloads, 16-bit size cap");
}

static void test_pcap_limit(void) {
    uint8_t frame[1024] = {0};
    assert(pcap_serializer_init());
    for (unsigned i = 0; i < 100; ++i) pcap_serializer_append_frame(frame, sizeof(frame), i);
    unsigned size = pcap_serializer_get_size();
    assert(size <= 65536 && size > 64000);
    pcap_serializer_append_frame(frame, sizeof(frame), 101); assert(pcap_serializer_get_size() == size);
    pcap_serializer_deinit(); assert(!pcap_serializer_get_buffer() && pcap_serializer_get_size() == 0);
    puts("PASS: bounded PCAP memory and cleanup");
}
static void test_start_failures(void) {
    fail_sniffer = true;
    assert(attack_submit(0, 1, 2, 5) == ESP_OK); dispatch();
    assert(!sniffing && !timer.armed && attack_get_status()->state == TIMEOUT);
    assert(attack_reset_request() == ESP_OK); dispatch();
    fail_sniffer = false; fail_connection = true;
    assert(attack_submit(0, 2, 0, 5) == ESP_OK); dispatch();
    assert(!sniffing && !timer.armed && attack_get_status()->state == TIMEOUT);
    assert(attack_reset_request() == ESP_OK); dispatch();
    fail_connection = false; fail_method = true;
    assert(attack_submit(0, 1, 0, 5) == ESP_OK); dispatch();
    assert(!sniffing && !timer.armed && attack_get_status()->state == TIMEOUT);
    assert(attack_reset_request() == ESP_OK); dispatch();
    assert(attack_submit(0, 3, 2, 5) == ESP_OK); dispatch();
    assert(!timer.armed && attack_get_status()->state == TIMEOUT);
    assert(attack_reset_request() == ESP_OK); dispatch();
    fail_method = false;
    puts("PASS: radio, connection and method start failures clean up without restarting");
}
static void test_pmkid_flow(void) {
    assert(attack_submit(0, 2, 0, 5) == ESP_OK); dispatch();
    uint8_t frame[256]; size_t size = make_frame(frame, 1, 7, 1);
    frame[35] += 22; frame[130] = 22;
    uint8_t kde[] = {221, 20, 0, 15, 172, 4};
    memcpy(frame + size, kde, sizeof(kde)); memset(frame + size + 6, 0x42, 16); size += 22;
    size_t total = sizeof(sniffer_frame_t) + sizeof(wifi_promiscuous_pkt_t) + size + 4;
    sniffer_frame_t *event = calloc(1, total); event->generation = generation;
    wifi_promiscuous_pkt_t *packet = (void *)event->packet;
    packet->rx_ctrl.sig_len = size + 4; memcpy(packet->payload, frame, size);
    assert(esp_event_post(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA, event, total, 0) == ESP_OK);
    free(event); dispatch();
    const attack_status_t *status = attack_get_status();
    assert(status->state == FINISHED && !sniffing && !timer.armed && status->content_size == 33);
    assert(!memcmp(status->content, frame + 4, 6)); /* Actual receiver, not ESP32's own MAC. */
    assert(!memcmp(status->content + 6, ap_mac, 6) && status->content[12] == 4);
    assert(!memcmp(status->content + 13, "test", 4) && status->content[17] == 0x42);
    assert(attack_reset_request() == ESP_OK); dispatch();
    puts("PASS: PMKID event delivery, actual receiver MAC, completed result and cleanup");
}

static void test_unified_jobs(void) {
    unsigned old_restored = restored;
    uint32_t scan = attack_get_job()->scan_generation;
    uint8_t index = 0, duplicate[] = {0,0};
    char boot[17]; strcpy(boot, attack_get_job()->boot_id);
    assert(attack_scan_submit() == ESP_OK);
    assert(attack_get_job()->scanning);
    assert(attack_submit_job(&index,1,1,2,5,scan) == ESP_ERR_INVALID_STATE);
    httpd_req_t req = {0};
    networks_get(&req); assert(!strcmp(req.status,"409 Conflict")); clear_response(&req);
    assert(attack_stop_request(boot,attack_get_job()->id) == ESP_ERR_INVALID_STATE);
    dispatch(); assert(!attack_is_running() && restored > old_restored);
    assert(attack_get_job()->scan_generation == ++scan);
    assert(attack_submit_job(&index,1,1,2,5,scan-1) == ESP_ERR_INVALID_STATE);
    assert(attack_submit_job(duplicate,2,4,0,5,scan) == ESP_ERR_INVALID_ARG);
    char response[2048];
    serial_console_execute("0,0",response,sizeof(response)); assert(strstr(response,"selected=1"));
    const char *invalid[] = {"0,,0","0,","0 0","starrt","limit 0","limit -1","limit 99999999999"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);++i) {
        serial_console_execute(invalid[i],response,sizeof(response));
        assert(!strstr(response,"accepted") && strstr(response,"selected=1"));
    }
    serial_console_execute("limit 3",response,sizeof(response)); assert(strstr(response,"accepted"));
    serial_console_execute("start",response,sizeof(response)); assert(strstr(response,"accepted"));
    uint32_t id=attack_get_job()->id;
    assert(attack_get_job()->timeout==3 && attack_get_job()->count==1);
    assert(attack_submit_job(&index,1,1,2,5,scan)==ESP_ERR_INVALID_STATE);
    dispatch(); assert(controlling);
    attack_note_tx(true,0); attack_note_tx(false,0);
    assert(attack_get_job()->sent==1 && attack_get_job()->tx_errors==1);
    assert(attack_stop_request("stale",id)==ESP_ERR_NOT_FOUND);
    assert(attack_stop_request(boot,id-1)==ESP_ERR_NOT_FOUND);
    serial_console_execute("cancel",response,sizeof(response)); assert(strstr(response,"selected=0"));
    dispatch(); assert(!controlling && !timer.armed && !strcmp(attack_get_job()->reason,"cancelled"));
    assert(attack_submit_job(&index,1,4,0,5,scan)==ESP_OK); dispatch();
    expire(); dispatch(); assert(!controlling && !strcmp(attack_get_job()->reason,"deadline"));
    old_restored=restored; fail_method=true;
    assert(attack_submit_job(&index,1,4,0,5,scan)==ESP_OK); dispatch(); fail_method=false;
    assert(!controlling && !timer.armed && restored>old_restored);
    /* Browser JSON validation and partial reads use the actual HTTP handlers. */
    char body[512];
    snprintf(body,sizeof(body),"{\"boot_id\":\"%s\",\"targets\":[0],\"type\":1,\"method\":2,\"timeout\":5,\"scan_generation\":%lu}",boot,(unsigned long)scan);
    req=(httpd_req_t){.body=body,.content_len=strlen(body),.chunk_limit=1};
    job_post(&req); assert(!strcmp(req.status,"202 Accepted")); clear_response(&req); dispatch();
    deliver_frame(1,generation); deliver_frame(2,generation);
    id=attack_get_job()->id;
    assert(attack_stop_request(boot,id)==ESP_OK); dispatch();
    char query[96]; snprintf(query,sizeof(query),"boot_id=%s&id=%lu",boot,(unsigned long)id);
    req=(httpd_req_t){.query=query,.user_ctx=(void *)1};
    capture_get(&req); assert(req.response_size>24 && !req.status); clear_response(&req);
    snprintf(query,sizeof(query),"boot_id=%s&id=%lu",boot,(unsigned long)(id-1));
    capture_get(&req); assert(!strcmp(req.status,"404 Not Found")); clear_response(&req);
    req.query="boot_id=stale&id=1"; capture_get(&req); assert(!strcmp(req.status,"404 Not Found")); clear_response(&req);
    req.query="boot_id=stale&id=-1"; capture_get(&req); assert(!strcmp(req.status,"400 Bad Request")); clear_response(&req);
    const char *bad_json[]={"{", "{}", "{} trailing", "[]", "{\"targets\":[0.5],\"type\":1}"};
    for(unsigned i=0;i<sizeof(bad_json)/sizeof(*bad_json);++i) {
        req=(httpd_req_t){.body=bad_json[i],.content_len=strlen(bad_json[i])};
        job_post(&req); assert(!strcmp(req.status,"400 Bad Request")); clear_response(&req);
    }
    /* A stop event from a completed run must not cancel the next run. */
    assert(attack_submit_job(&index,1,4,0,5,scan)==ESP_OK); dispatch();
    id=attack_get_job()->id; assert(attack_stop_request(boot,id)==ESP_OK);
    expire(); /* Timeout queued after stop: both must be harmless after completion. */
    dispatch(); assert(!attack_is_running());
    assert(attack_submit_job(&index,1,4,0,5,scan)==ESP_OK); dispatch(); assert(controlling);
    assert(attack_stop_request(boot,id)==ESP_ERR_NOT_FOUND);
    assert(attack_stop_request(boot,attack_get_job()->id)==ESP_OK); dispatch();
    /* Eight strongest targets, copied rather than aliasing the scanner table. */
    wifi_ap_record_t saved=aps.records[0]; aps.count=10;
    for(unsigned i=0;i<10;++i) {
        aps.records[i]=saved; aps.records[i].bssid[5]=i+1; aps.records[i].rssi=-100+(int)i;
    }
    serial_console_execute("all",response,sizeof(response)); assert(strstr(response,"selected=8"));
    serial_console_execute("start",response,sizeof(response)); assert(strstr(response,"accepted")); dispatch();
    assert(attack_get_job()->count==8 && attack_get_job()->targets[0].bssid[5]==10);
    aps.records[9].bssid[5]=99; assert(attack_get_job()->targets[0].bssid[5]==10);
    serial_console_execute("cancel",response,sizeof(response)); dispatch();
    aps.count=1; aps.records[0]=saved;
    assert(attack_reset_request()==ESP_OK); dispatch();
    puts("PASS: shared browser/serial jobs, conflicts, scan generations, counters, timed stop, failed start restoration, capture IDs, strict JSON, eight-target snapshots");
}

int main(void) {
    test_parser_bounds(); test_pmkid(); test_handshakes(); test_security_report();
    test_lifecycle_and_http(); test_start_failures(); test_pmkid_flow(); test_pcap_limit(); test_unified_jobs();
    puts("All core regression tests passed."); return 0;
}
