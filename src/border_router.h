/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Identify the Thread border router this device is attached to.
 *
 * Warema's central question is whether their product behaves the same on every
 * commercially available gateway. Answering it at fleet scale needs the gateway
 * to be a dimension you can segment on, which means the device has to report
 * who made it.
 *
 * Mechanism: Thread 1.3 network diagnostics. We ask the parent for TLV 25
 * (Vendor Name) and TLV 26 (Vendor Model) and report whatever it says.
 *
 * Why not OUI lookup on the parent's extended address: border routers use
 * locally administered EUI-64s. Verified on a Google Nest, whose parent
 * extended address a62d405ee2e5cd52 has the local bit set — there is no
 * manufacturer encoded in it. An OUI table would read "unknown" on every
 * gateway, forever.
 *
 * Two honest limitations:
 *  - On a mesh with several routers the parent need not be the border router.
 *    The answer is then "the router we are attached to", which is still the
 *    device that shapes our connectivity.
 *  - A gateway may not implement the vendor TLVs. That is recorded as a query
 *    failure rather than guessed at.
 */

#define BR_VENDOR_STR_MAX 33   /* 32 chars + NUL, per OT_NETWORK_DIAGNOSTIC_MAX_* */

struct border_router_info {
	char     vendor_name[BR_VENDOR_STR_MAX];
	char     vendor_model[BR_VENDOR_STR_MAX];
	bool     valid;            /* a diagnostics response has been received */
	uint32_t query_failures;   /* cumulative, for the heartbeat metric */
};

/*
 * Kick off a diagnostics query to the current parent. Non-blocking: the
 * response arrives on an OpenThread callback. Safe to call repeatedly; it is
 * rate-limited internally so a flapping parent cannot generate query storms.
 *
 * Must NOT be called with the OpenThread mutex held.
 */
void border_router_query(void);

/* Snapshot whatever is currently known. Never blocks. */
void border_router_get(struct border_router_info *out);

#ifdef __cplusplus
}
#endif
