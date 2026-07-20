/*
 * device_auth_main.c — Full EDHOC handshake with Python gateway via serial.
 *
 * Output (mote -> socket): hex lines via LOG_INFO (goes through simLoggedData).
 * Input  (socket -> mote): custom rs232 byte handler accumulating into a large
 *   buffer, because the serial-line ring buffer is uint8_t-limited to 128 bytes
 *   and our MSG_2 line is ~258 bytes.
 *
 * Flow:
 *   1. Build MSG_1
 *   2. Send MSG_1 over serial (hex-encoded, one line)
 *   3. Wait for MSG_2 from serial (custom handler reassembles the line)
 *   4. Process MSG_2, derive session key
 *   5. Print session key
 */

#include "contiki.h"
#include "device_auth.h"
#include "credentials.h"
#include "sys/energest.h"
#include "sys/log.h"
/* rs232 stubbed for cc2538dk footprint build */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LOG_MODULE "DeviceAuth"
#define LOG_LEVEL  LOG_LEVEL_INFO

/* ---------------------------------------------------------------------------
 * Custom serial input: bypass the 128-byte serial-line ring buffer.
 * Cooja feeds every incoming byte to this handler (set via rs232_set_input).
 * We accumulate until newline, then raise msg2_ready for the process to poll.
 * --------------------------------------------------------------------------- */
#define MSG2_LINE_MAX 600
static volatile uint8_t msg2_ready = 0;
static char           msg2_line[MSG2_LINE_MAX];
static volatile int   msg2_pos = 0;

static int __attribute__((unused)) serial_input_byte(unsigned char c)
{
    if(c == '\n' || c == '\r') {
        if(msg2_pos > 0 && !msg2_ready) {
            msg2_line[msg2_pos] = '\0';
            msg2_ready = 1;
            return 1;   /* wake CPU */
        }
        return 0;
    }
    if(msg2_pos < MSG2_LINE_MAX - 1) {
        msg2_line[msg2_pos++] = (char)c;
    }
    return 0;
}

/* Hex encoding helpers */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    /* Build hex string into a static buffer then emit via LOG_INFO
     * so it travels through the Cooja serial socket. */
    static char hex_buf[600];
    size_t pos = 0;
    size_t label_len = strlen(label);

    memcpy(hex_buf, label, label_len);
    pos += label_len;
    hex_buf[pos++] = ':';

    for(size_t i = 0; i < len && pos + 2 < sizeof(hex_buf) - 1; i++) {
        hex_buf[pos++] = "0123456789abcdef"[data[i] >> 4];
        hex_buf[pos++] = "0123456789abcdef"[data[i] & 0xf];
    }
    hex_buf[pos] = '\0';

    LOG_INFO("%s\n", hex_buf);
}

static int parse_hex(const char *hex, uint8_t *out, size_t max_len)
{
    size_t hex_len = strlen(hex);
    if(hex_len % 2 != 0 || hex_len / 2 > max_len) { return -1; }
    for(size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if(sscanf(hex + 2*i, "%02x", &byte) != 1) { return -1; }
        out[i] = (uint8_t)byte;
    }
    return (int)(hex_len / 2);
}

/*---------------------------------------------------------------------------*/
PROCESS(device_auth_process, "Device Auth Process");
AUTOSTART_PROCESSES(&device_auth_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(device_auth_process, ev, data)
{
    static device_auth_state_t auth_state;
    static uint8_t msg1_buf[256];
    static uint8_t msg2_buf[256];
    static uint8_t session_key[AUTH_SESSION_KEY_LEN];
    static int msg1_len;
    static struct etimer et;
    static struct etimer poll_et;
    char *line;
    int msg2_len;
    int ret;

    PROCESS_BEGIN();

    /* Install custom byte handler for incoming MSG_2 (bypasses serial-line). */
    /* rs232 stubbed */

    LOG_INFO("=== L-ECQV + DID Authentication Demo ===\n");
    LOG_INFO("Waiting for simulation to stabilize...\n");

    /* Delay to let the serial socket connect before sending MSG_1. */
    etimer_set(&et, CLOCK_SECOND * 10);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    energest_init();

    /* Build MSG_1 */
    LOG_INFO("Building MSG_1...\n");
    msg1_len = device_auth_build_msg1(&auth_state, msg1_buf, sizeof(msg1_buf));

    if(msg1_len < 0) {
        LOG_ERR("MSG_1 build failed: %d\n", msg1_len);
        PROCESS_EXIT();
    }

    LOG_INFO("MSG_1 built: %d bytes\n", msg1_len);

    /* Send MSG_1 as hex over serial */
    print_hex("MSG1", msg1_buf, msg1_len);

    /* Wait for MSG_2: poll the ready flag set by the custom handler. */
    LOG_INFO("Waiting for MSG_2 from gateway...\n");
    while(!msg2_ready) {
        etimer_set(&poll_et, CLOCK_SECOND / 10);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&poll_et));
    }

    /* Parse MSG_2 from hex */
    line = msg2_line;
    msg2_len = -1;

    if(strncmp(line, "MSG2:", 5) == 0) {
        msg2_len = parse_hex(line + 5, msg2_buf, sizeof(msg2_buf));
    }

    if(msg2_len < 0) {
        LOG_ERR("MSG_2 parse failed (line: %.16s...)\n", line);
        PROCESS_EXIT();
    }

    LOG_INFO("MSG_2 received: %d bytes\n", msg2_len);

    /* Process MSG_2 */
    ret = device_auth_process_msg2(
        &auth_state,
        msg2_buf, msg2_len,
        session_key
    );

    if(ret == AUTH_OK) {
        LOG_INFO("=== Authentication Successful ===\n");
        print_hex("SESSION_KEY", session_key, AUTH_SESSION_KEY_LEN);
    } else {
        LOG_ERR("Authentication failed: %d\n", ret);
    }

    energest_flush();
    LOG_INFO("CPU ticks: %llu\n",
             (unsigned long long)energest_type_time(ENERGEST_TYPE_CPU));
    LOG_INFO("=== Done ===\n");

    PROCESS_END();
}
