/*
 * device_auth_main.c — Contiki-NG process for ECQV+DID authentication.
 */
#include "contiki.h"
#include "device_auth.h"
#include "credentials.h"
#include "sys/energest.h"
#include "sys/log.h"
#include <stdio.h>
#include <string.h>

#define LOG_MODULE "DeviceAuth"
#define LOG_LEVEL  LOG_LEVEL_INFO

static const uint8_t PLACEHOLDER_MSG2[] = { 0x00 };
static const size_t  PLACEHOLDER_MSG2_LEN = 0;

PROCESS(device_auth_process, "Device Auth Process");
AUTOSTART_PROCESSES(&device_auth_process);

PROCESS_THREAD(device_auth_process, ev, data)
{
    static device_auth_state_t auth_state;
    static uint8_t msg1_buf[256];
    static uint8_t session_key[AUTH_SESSION_KEY_LEN];

    PROCESS_BEGIN();

    LOG_INFO("=== L-ECQV + DID Authentication Demo ===\n");
    LOG_INFO("  DEVICE_PRIVATE_KEY: %u bytes\n", DEVICE_PRIVATE_KEY_LEN);
    LOG_INFO("  DEVICE_CERT_R:      %u bytes\n", DEVICE_CERT_R_LEN);
    LOG_INFO("  DEVICE_CERT_INFO:   %u bytes\n", DEVICE_CERT_INFO_LEN);
    LOG_INFO("  GATEWAY_PUBLIC_KEY: %u bytes\n", GATEWAY_PUBLIC_KEY_LEN);
    LOG_INFO("  ISSUER_PUBLIC_KEY:  %u bytes\n", ISSUER_PUBLIC_KEY_LEN);

    energest_init();

    LOG_INFO("Building MSG_1...\n");
    int msg1_len = device_auth_build_msg1(&auth_state, msg1_buf, sizeof(msg1_buf));

    if(msg1_len < 0) {
        LOG_ERR("MSG_1 build failed: %d\n", msg1_len);
        PROCESS_EXIT();
    }
    LOG_INFO("MSG_1 ready: %d bytes\n", msg1_len);

    if(PLACEHOLDER_MSG2_LEN > 0) {
        LOG_INFO("Processing MSG_2...\n");
        int ret = device_auth_process_msg2(
            &auth_state,
            PLACEHOLDER_MSG2, PLACEHOLDER_MSG2_LEN,
            session_key);
        if(ret == AUTH_OK) {
            LOG_INFO("Authentication complete.\n");
        } else {
            LOG_ERR("MSG_2 failed: %d\n", ret);
        }
    } else {
        LOG_INFO("MSG_2 placeholder empty - MSG_1 measurement only.\n");
    }

    energest_flush();
    LOG_INFO("=== Energest Report ===\n");
    LOG_INFO("  CPU:      %llu ticks\n",
             (unsigned long long)energest_type_time(ENERGEST_TYPE_CPU));
    LOG_INFO("  Radio TX: %llu ticks\n",
             (unsigned long long)energest_type_time(ENERGEST_TYPE_TRANSMIT));
    LOG_INFO("  Radio RX: %llu ticks\n",
             (unsigned long long)energest_type_time(ENERGEST_TYPE_LISTEN));
    LOG_INFO("=== Done ===\n");

    PROCESS_END();
}
