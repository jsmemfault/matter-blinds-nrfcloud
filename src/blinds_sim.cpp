/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Simulated shade duty cycle. See blinds_sim.h.
 */

#include "blinds_sim.h"
#include "blinds.h"

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/logging/log.h>

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app/clusters/window-covering-server/window-covering-server.h>
#include <platform/CHIPDeviceLayer.h>

#ifdef CONFIG_MEMFAULT
#include <memfault/core/trace_event.h>
#include <memfault/metrics/metrics.h>
#endif

LOG_MODULE_REGISTER(blinds_sim, LOG_LEVEL_INF);

using namespace chip;
using namespace chip::app::Clusters;

namespace
{

constexpr EndpointId kEndpoint = 1;

/* Positions are hundredths of a percent: 0 = fully open, 10000 = fully closed. */
constexpr uint16_t kOpen = 0;
constexpr uint16_t kClosed = 10000;

atomic_t s_travel_pct;
atomic_t s_obstructions;
atomic_t s_motor_current_ma;

/*
 * A compressed day. One simulated day per SIM_DAY_SEC of wall clock, so a
 * dashboard fills with plausible duty cycle in minutes rather than weeks.
 * Deliberately not 1:1 — this exists to exercise metrics, not to be a clock.
 */
constexpr int kSimDaySec = CONFIG_BLINDS_SIM_DAY_SECONDS;

struct SimStep {
	uint16_t    lift;       /* target lift position */
	uint16_t    tilt;       /* target tilt position */
	const char *label;
};

/*
 * A residential shade's actual day: open at breakfast, tilt against midday
 * sun, reopen in the afternoon, close at dusk. Four moves a day is roughly
 * 1,460 a year, which is the duty figure that matters for mechanical wear.
 */
const SimStep kDay[] = {
	{ kOpen,  2000, "morning open" },
	{ 3000,   7000, "midday sun" },
	{ kOpen,  3000, "afternoon" },
	{ kClosed, kClosed, "dusk close" },
};

uint32_t rand_range(uint32_t lo, uint32_t hi)
{
	if (hi <= lo) {
		return lo;
	}
	return lo + (sys_rand32_get() % (hi - lo + 1));
}

uint16_t current_lift()
{
	chip::app::DataModel::Nullable<chip::Percent100ths> pos;

	DeviceLayer::PlatformMgr().LockChipStack();
	WindowCovering::Attributes::CurrentPositionLiftPercent100ths::Get(kEndpoint, pos);
	DeviceLayer::PlatformMgr().UnlockChipStack();

	return pos.IsNull() ? kOpen : pos.Value();
}

/*
 * Issue a movement the way a controller would: write the target attribute and
 * let the sample's window covering driver run the motion. The resulting
 * OperationalStatus transitions are what blinds.cpp reports.
 */
void drive_to(uint16_t lift, uint16_t tilt)
{
	DeviceLayer::PlatformMgr().LockChipStack();
	WindowCovering::Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, lift);
	WindowCovering::Attributes::TargetPositionTiltPercent100ths::Set(kEndpoint, tilt);
	DeviceLayer::PlatformMgr().UnlockChipStack();
}

void sim_thread(void *, void *, void *)
{
	/* Let Matter finish initialising before writing attributes. */
	k_sleep(K_SECONDS(20));
	LOG_INF("Shade simulation started (%d s per simulated day)", kSimDaySec);

	size_t step = 0;

	while (true) {
		const SimStep &s = kDay[step % ARRAY_SIZE(kDay)];
		uint16_t from = current_lift();

		/*
		 * Movement session: one Memfault report per move. A binding
		 * mechanism shows up as peak current trending across thousands
		 * of units, which a heartbeat average would hide.
		 */
#ifdef CONFIG_MEMFAULT
		MEMFAULT_METRICS_SESSION_START(blinds_movement);
#endif
		int64_t t0 = k_uptime_get();

		blinds_record_move_start();
		drive_to(s.lift, s.tilt);

		/* Nominal shade speed: full travel in ~12 s. */
		uint32_t distance_pct =
			(uint32_t)((from > s.lift ? from - s.lift : s.lift - from) / 100);
		uint32_t travel_ms = 1200 + distance_pct * 120;

		/* Running current scales with load; add spread so trends exist. */
		uint32_t nominal_ma = rand_range(180, 240);
		uint32_t peak_ma = nominal_ma;
		uint32_t stalls = 0;

		atomic_set(&s_motor_current_ma, (atomic_val_t)nominal_ma);

		/*
		 * Fault injection. Rates chosen to be visible on a dashboard in
		 * an afternoon rather than to model a real failure distribution:
		 * roughly 1 move in 12 stalls, 1 in 25 hits an obstruction.
		 */
		bool will_stall = (rand_range(1, 12) == 1);
		bool will_obstruct = (rand_range(1, 25) == 1);

		if (will_stall) {
			stalls++;
			peak_ma = rand_range(400, 650);
			atomic_set(&s_motor_current_ma, (atomic_val_t)peak_ma);
			blinds_record_stall();
#ifdef CONFIG_MEMFAULT
			MEMFAULT_TRACE_EVENT_WITH_LOG(blinds_stall,
				"%s: stall at %u%%, %u mA", s.label,
				(unsigned)(from / 100), (unsigned)peak_ma);
			MEMFAULT_METRIC_SESSION_SET_UNSIGNED(move_stalls,
							     blinds_movement, stalls);
#endif
			LOG_WRN("simulated stall during %s (%u mA)", s.label,
				(unsigned)peak_ma);
		}

		if (will_obstruct) {
			atomic_inc(&s_obstructions);
			peak_ma = MAX(peak_ma, rand_range(500, 800));
			atomic_set(&s_motor_current_ma, (atomic_val_t)peak_ma);
#ifdef CONFIG_MEMFAULT
			MEMFAULT_TRACE_EVENT_WITH_LOG(blinds_obstruction,
				"%s: obstruction, %u mA", s.label,
				(unsigned)peak_ma);
#endif
			LOG_WRN("simulated obstruction during %s", s.label);
		}

		k_sleep(K_MSEC(travel_ms));

		atomic_add(&s_travel_pct, (atomic_val_t)distance_pct);
		atomic_set(&s_motor_current_ma, 0);

#ifdef CONFIG_MEMFAULT
		MEMFAULT_METRIC_SESSION_SET_UNSIGNED(
			move_duration_ms, blinds_movement,
			(uint32_t)(k_uptime_get() - t0));
		MEMFAULT_METRIC_SESSION_SET_UNSIGNED(
			move_distance_pct, blinds_movement, distance_pct);
		MEMFAULT_METRIC_SESSION_SET_UNSIGNED(
			move_peak_current_ma, blinds_movement, peak_ma);
		MEMFAULT_METRICS_SESSION_END(blinds_movement);
#endif

		step++;
		k_sleep(K_SECONDS(kSimDaySec / (int)ARRAY_SIZE(kDay)));
	}
}

} /* namespace */

uint32_t blinds_sim_motor_current_ma(void)
{
	return (uint32_t)atomic_get(&s_motor_current_ma);
}

uint32_t blinds_sim_take_travel_pct(void)
{
	return (uint32_t)atomic_set(&s_travel_pct, 0);
}

uint32_t blinds_sim_take_obstructions(void)
{
	return (uint32_t)atomic_set(&s_obstructions, 0);
}

K_THREAD_DEFINE(blinds_sim_tid, 4096, sim_thread, NULL, NULL, NULL,
		K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);
