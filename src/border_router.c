/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Border router identification over Thread network diagnostics.
 * See border_router.h for why OUI lookup is not an option.
 */

#include "border_router.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <openthread.h>
#include <openthread/dataset.h>
#include <openthread/netdiag.h>
#include <openthread/thread.h>

#include <string.h>

LOG_MODULE_REGISTER(border_router, LOG_LEVEL_INF);

/*
 * A diagnostics request is a real network round trip. On a sleepy end device
 * it also forces a wake, so this is deliberately infrequent: the answer only
 * changes when the parent changes, which is rare.
 */
#define QUERY_MIN_INTERVAL_MS (10 * 60 * 1000)

/* Response arrives on the OpenThread work queue; readers are the telemetry
 * thread and the shell. A mutex is enough — no ISR touches this. */
static K_MUTEX_DEFINE(s_lock);

static struct border_router_info s_info;
static int64_t s_last_query_ms;
static bool s_query_outstanding;

static const uint8_t s_tlv_types[] = {
	OT_NETWORK_DIAGNOSTIC_TLV_VENDOR_NAME,
	OT_NETWORK_DIAGNOSTIC_TLV_VENDOR_MODEL,
};

static void diag_response_cb(otError error, otMessage *message,
			     const otMessageInfo *message_info, void *context)
{
	ARG_UNUSED(message_info);
	ARG_UNUSED(context);

	k_mutex_lock(&s_lock, K_FOREVER);
	s_query_outstanding = false;

	if (error != OT_ERROR_NONE || message == NULL) {
		/*
		 * A gateway that does not answer is itself a result — some
		 * border routers do not implement the vendor TLVs. Record it
		 * rather than inventing a vendor.
		 */
		s_info.query_failures++;
		k_mutex_unlock(&s_lock);
		LOG_WRN("border router diagnostics failed: %d", error);
		return;
	}

	otNetworkDiagIterator iter = OT_NETWORK_DIAGNOSTIC_ITERATOR_INIT;
	otNetworkDiagTlv tlv;

	while (otThreadGetNextDiagnosticTlv(message, &iter, &tlv) == OT_ERROR_NONE) {
		switch (tlv.mType) {
		case OT_NETWORK_DIAGNOSTIC_TLV_VENDOR_NAME:
			strncpy(s_info.vendor_name, tlv.mData.mVendorName,
				sizeof(s_info.vendor_name) - 1);
			s_info.vendor_name[sizeof(s_info.vendor_name) - 1] = '\0';
			s_info.valid = true;
			break;
		case OT_NETWORK_DIAGNOSTIC_TLV_VENDOR_MODEL:
			strncpy(s_info.vendor_model, tlv.mData.mVendorModel,
				sizeof(s_info.vendor_model) - 1);
			s_info.vendor_model[sizeof(s_info.vendor_model) - 1] = '\0';
			s_info.valid = true;
			break;
		default:
			break;
		}
	}

	bool valid = s_info.valid;
	char name[BR_VENDOR_STR_MAX];
	char model[BR_VENDOR_STR_MAX];

	strcpy(name, s_info.vendor_name);
	strcpy(model, s_info.vendor_model);
	k_mutex_unlock(&s_lock);

	if (valid) {
		LOG_INF("border router: vendor=\"%s\" model=\"%s\"", name, model);
	} else {
		LOG_WRN("border router answered with no vendor TLVs");
	}
}

void border_router_query(void)
{
	otInstance *instance = openthread_get_default_instance();

	if (instance == NULL) {
		return;
	}

	int64_t now = k_uptime_get();

	k_mutex_lock(&s_lock, K_FOREVER);
	bool skip = s_query_outstanding ||
		    (s_last_query_ms != 0 &&
		     (now - s_last_query_ms) < QUERY_MIN_INTERVAL_MS);
	k_mutex_unlock(&s_lock);

	if (skip) {
		return;
	}

	openthread_mutex_lock();

	otRouterInfo parent;
	otError err = otThreadGetParentInfo(instance, &parent);
	otIp6Address dest;

	if (err == OT_ERROR_NONE) {
		/*
		 * Address the parent by its RLOC rather than a link-local
		 * address: the mesh-local prefix plus the RLOC16 locator is
		 * always routable from a child, whereas the parent's
		 * link-local address is not exposed by otRouterInfo.
		 */
		const otMeshLocalPrefix *ml = otThreadGetMeshLocalPrefix(instance);

		memset(&dest, 0, sizeof(dest));
		memcpy(dest.mFields.m8, ml->m8, OT_MESH_LOCAL_PREFIX_SIZE);
		dest.mFields.m8[8] = 0x00;
		dest.mFields.m8[9] = 0x00;
		dest.mFields.m8[10] = 0x00;
		dest.mFields.m8[11] = 0xff;
		dest.mFields.m8[12] = 0xfe;
		dest.mFields.m8[13] = 0x00;
		dest.mFields.m8[14] = (uint8_t)(parent.mRloc16 >> 8);
		dest.mFields.m8[15] = (uint8_t)(parent.mRloc16 & 0xff);

		err = otThreadSendDiagnosticGet(instance, &dest, s_tlv_types,
						ARRAY_SIZE(s_tlv_types),
						diag_response_cb, NULL);
	}

	openthread_mutex_unlock();

	k_mutex_lock(&s_lock, K_FOREVER);
	s_last_query_ms = now;
	if (err == OT_ERROR_NONE) {
		s_query_outstanding = true;
	} else {
		s_info.query_failures++;
	}
	k_mutex_unlock(&s_lock);

	if (err != OT_ERROR_NONE) {
		LOG_WRN("border router query not sent: %d", err);
	}
}

void border_router_get(struct border_router_info *out)
{
	if (out == NULL) {
		return;
	}

	k_mutex_lock(&s_lock, K_FOREVER);
	*out = s_info;
	k_mutex_unlock(&s_lock);
}
