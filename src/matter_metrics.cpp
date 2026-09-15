/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "matter_metrics.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/logging/log.h>

#include <platform/CHIPDeviceLayer.h>
#include <app/server/Server.h>
#include <app/InteractionModelEngine.h>
#include <app/ReadHandler.h>

#ifdef CONFIG_MEMFAULT
#include <memfault/metrics/metrics.h>
#endif

LOG_MODULE_REGISTER(matter_metrics, LOG_LEVEL_INF);

static atomic_t s_commissioning_count;
static atomic_t s_case_failures;
static atomic_t s_subscription_teardowns;

static void matter_event_handler(const chip::DeviceLayer::ChipDeviceEvent *event,
				  intptr_t /* arg */)
{
	switch (event->Type) {
	case chip::DeviceLayer::DeviceEventType::kCommissioningComplete:
		atomic_inc(&s_commissioning_count);
		break;
	default:
		break;
	}
}

void matter_metrics_init(void)
{
	chip::DeviceLayer::PlatformMgr().AddEventHandler(matter_event_handler, 0);
}

void matter_metrics_record_case_failure(void)
{
	atomic_inc(&s_case_failures);
}

void matter_metrics_record_subscription_teardown(void)
{
	atomic_inc(&s_subscription_teardowns);
}

void matter_metrics_collect(void)
{
#ifdef CONFIG_MEMFAULT
	/* Flush event counters atomically */
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(matter_commissioning_count),
		(uint32_t)atomic_set(&s_commissioning_count, 0));
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(matter_case_failures),
		(uint32_t)atomic_set(&s_case_failures, 0));
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(matter_subscription_teardowns),
		(uint32_t)atomic_set(&s_subscription_teardowns, 0));

	/* Snapshot metrics — requires chip stack lock */
	chip::DeviceLayer::PlatformMgr().LockChipStack();

	auto &fabric_table = chip::Server::GetInstance().GetFabricTable();
	uint8_t fabric_count = fabric_table.FabricCount();
	uint16_t sub_count =
		chip::app::InteractionModelEngine::GetInstance()->GetNumActiveReadHandlers(
			chip::app::ReadHandler::InteractionType::Subscribe);

	/*
	 * Vendor ID of the ecosystem that commissioned us: 0x1349 Apple,
	 * 0x6006 Google, 0x1217 Amazon, 0x1049 SmartThings.
	 *
	 * This is what makes every other metric in this file actionable. Pushed
	 * to Memfault as a device attribute, it lets the whole fleet be sliced by
	 * ecosystem — so "our detached time is 4x worse on Google than Apple"
	 * becomes a query instead of a guess.
	 *
	 * Reports the first fabric found. A device commissioned into several
	 * ecosystems is a genuinely different case and worth reporting separately
	 * rather than collapsing to one ID.
	 */
	uint16_t admin_vendor_id = 0;

	for (const auto &fabric : fabric_table) {
		admin_vendor_id = static_cast<uint16_t>(fabric.GetVendorId());
		break;
	}

	chip::DeviceLayer::PlatformMgr().UnlockChipStack();

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(matter_admin_vendor_id), admin_vendor_id);

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(matter_fabric_count), fabric_count);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(matter_subscriptions_active), sub_count);
#endif
}
