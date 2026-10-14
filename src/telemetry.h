/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Upload cost, filled in by the transport and reported per heartbeat.
 *
 * Broken out per phase because the phases have very different causes:
 * handshake is crypto and round trips, auth is server-side, and the total is
 * what the battery actually pays.
 */
struct telemetry_timing {
	uint32_t handshake_ms;   /* DTLS handshake */
	uint32_t auth_ms;        /* POST /auth/jwt round trip */
	uint32_t connect_ms;     /* resolve + handshake + auth */
	uint32_t chunks_sent;    /* delta, reset each heartbeat */
	uint32_t bytes_sent;     /* delta, reset each heartbeat */
};

extern struct telemetry_timing telemetry_timing;

/* Record a failed nRF Cloud upload attempt. */
void telemetry_record_upload_err(void);

/*
 * Ask the telemetry thread to collect and upload immediately rather than
 * waiting out the upload interval. Safe from any thread.
 */
void telemetry_request_upload(void);

#ifdef __cplusplus
}
#endif
