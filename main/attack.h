/**
 * @file attack.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-02
 * @copyright Copyright (c) 2021
 *
 * @brief Provides interface to attack wrapper
 * 
 * This file provide interface to control attack wrapper like setting current attack state, 
 * update attack status content, etc...
 */

#ifndef ATTACK_H
#define ATTACK_H

#include "esp_wifi_types.h"
#include "esp_err.h"
#include <stdbool.h>

/**
 * @brief Implemented attack types that can be chosen.
 * 
 */
typedef enum {
    ATTACK_TYPE_PASSIVE,
    ATTACK_TYPE_HANDSHAKE,
    ATTACK_TYPE_PMKID,
    ATTACK_TYPE_DOS
} attack_type_t;

/**
 * @brief States of single attack run. 
 * 
 * @note TIMEOUT will be removed in #64
 */
typedef enum {
    READY,      ///< no attack is in progress and results from previous attack run are available.
    RUNNING,    ///< attack is in progress, attack_status_t.content may not be consistent.
    FINISHED,   ///< last attack finsihed and results are available.
    TIMEOUT     ///< last attack timed out. This option will be moved as sub category of FINISHED state.
} attack_state_t;

/**
 * @brief Attack config parsed from webserver request
 * 
 * @deprecated will be removed in #45
 */
typedef struct {
    uint8_t type;
    uint8_t method;
    uint8_t timeout;
    const wifi_ap_record_t *ap_record;
} attack_config_t;

/**
 * @brief Contains current attack status.
 * 
 * This structure contains all information and data about latest attack.
 */
typedef struct {
    uint8_t state;  ///< attack_state_t
    uint8_t type;   ///< attack_type_t
    uint16_t content_size;
    char *content;
} attack_status_t;

enum { ATTACK_TYPE_CONTROLLER = 4, MAX_JOB_TARGETS = 8 };
typedef struct {
    char boot_id[17];
    uint32_t id, scan_generation, sent, tx_errors, channel_errors;
    /* sent is the legacy name for SDK-accepted submissions, not peer receipt. */
    uint32_t tx_done_ok, tx_done_fail;
    bool tx_callback_registered;
    esp_err_t tx_callback_error;
    esp_err_t radio_error;
    char radio_stage[16];
    uint8_t type, method, timeout, count, current_target, ssid_len;
    uint8_t ssid[32];
    wifi_ap_record_t targets[MAX_JOB_TARGETS];
    int pmf;
    int64_t started_us, ended_us;
    bool scanning, stopping;
    char reason[48];
} attack_job_t;
/* Read only while holding attack_lock. Copies contain no borrowed pointers. */
const attack_job_t *attack_get_job(void);
esp_err_t attack_submit_job(const uint8_t *indices, unsigned count, uint8_t type,
                           uint8_t method, uint8_t timeout, uint32_t scan_generation);
esp_err_t attack_scan_submit(void);
esp_err_t attack_legacy_scan(void);
esp_err_t attack_stop_request(const char *boot_id, uint32_t id);
void attack_note_tx(bool success, unsigned target);
/* Called by the manager after the controller stops; never from the Wi-Fi callback. */
void attack_controller_diagnostics(uint32_t id, uint32_t ok, uint32_t failed,
                                   bool registered, esp_err_t callback_error);
/* Called by the controller after its radio calls have stopped. Job identity guards
 * against late failure notifications affecting a later operation. */
esp_err_t attack_controller_failure_request(uint32_t id, esp_err_t error,
                                           const char *stage, unsigned target);
void attack_set_error(const char *reason);
void attack_note_setup_failure(esp_err_t error, const char *stage);

/**
 * @brief Returns pointer to attack_status_t structure.
 * 
 * @return const attack_status_t*  pointer to the status strucutre
 */
/* Hold attack_lock while reading status or capture buffers from another task. */
const attack_status_t *attack_get_status(void);
void attack_lock(void);
void attack_unlock(void);
bool attack_is_running(void);
esp_err_t attack_submit(uint8_t ap_index, uint8_t type, uint8_t method, uint8_t timeout);
esp_err_t attack_reset_request(void);

/**
 * @brief Function to update current status of attack.
 * 
 * If FINISHED state is passed, then the attack timeout timer is stopped.
 * @param state new attack state of type attack_state_t to be set
 */
void attack_update_status(attack_state_t state);

/**
 * @brief Initialises attack wrapper. This function should be callend only once.
 * 
 * This function creates all necessary resources for attack wrapper. It has to be called before any attack can be run.
 */
void attack_init();

/**
 * @brief Allocates status content of given size.
 *  
 * @param size size to be allocated
 * @return char* pointer to newly allocated status content
 */
char *attack_alloc_result_content(unsigned size);

/**
 * @brief Reallocates current status content and appends new data.
 * 
 * @param buffer new data to be appended to status content
 * @param size size of the new data to be appended
 */
void attack_append_status_content(uint8_t *buffer, unsigned size);

#endif
