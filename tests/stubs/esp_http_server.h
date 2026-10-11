#pragma once
#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>
#define HTTPD_RESP_USE_STRLEN -1
#define HTTPD_TYPE_OCTET "application/octet-stream"
#define HTTPD_SOCK_ERR_TIMEOUT -3
#define HTTP_GET 0
#define HTTP_POST 1
#define HTTP_HEAD 2
typedef struct { size_t content_len; void *user_ctx; const char *body; size_t position, chunk_limit; int recv_error; const char *status; uint8_t *response; size_t response_size; const char *query; } httpd_req_t;
typedef int *httpd_handle_t;
typedef struct { unsigned max_uri_handlers, stack_size; } httpd_config_t;
#define HTTPD_DEFAULT_CONFIG() ((httpd_config_t){.max_uri_handlers = 8})
typedef struct { const char *uri; int method; esp_err_t (*handler)(httpd_req_t *); void *user_ctx; } httpd_uri_t;
esp_err_t httpd_resp_set_status(httpd_req_t *, const char *);
esp_err_t httpd_resp_set_type(httpd_req_t *, const char *);
esp_err_t httpd_resp_set_hdr(httpd_req_t *, const char *, const char *);
esp_err_t httpd_resp_send(httpd_req_t *, const char *, int);
esp_err_t httpd_resp_send_chunk(httpd_req_t *, const char *, int);
int httpd_req_recv(httpd_req_t *, char *, size_t);
esp_err_t httpd_start(httpd_handle_t *, const httpd_config_t *);
esp_err_t httpd_register_uri_handler(httpd_handle_t, const httpd_uri_t *);
esp_err_t httpd_req_get_url_query_str(httpd_req_t *, char *, size_t);
esp_err_t httpd_query_key_value(const char *, const char *, char *, size_t);
