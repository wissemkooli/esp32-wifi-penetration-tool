#ifndef SECURITY_REPORT_H
#define SECURITY_REPORT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    PMF_UNKNOWN, PMF_NOT_ADVERTISED, PMF_CAPABLE, PMF_REQUIRED, PMF_INCONSISTENT
} pmf_status_t;
typedef struct {
    uint8_t bssid[6];
    pmf_status_t pmf;
    bool rsn_seen;
    bool ssid_seen;
    uint8_t ssid_len, ssid[32];
} security_observation_t;

/* Parse a complete beacon/probe response, excluding its FCS. */
bool security_parse_advertisement(const uint8_t *frame, size_t size,
                                  security_observation_t *result);
const char *security_pmf_name(pmf_status_t status);
#endif
