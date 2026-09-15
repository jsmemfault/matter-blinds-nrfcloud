/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Observability view of the window covering — reads live Matter attributes.
 * See blinds.h.
 */

#include "blinds.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>

#include <platform/CHIPDeviceLayer.h>
#include <app/clusters/window-covering-server/window-covering-server.h>
#include <app-common/zap-generated/attributes/Accessors.h>

using namespace chip;
using namespace chip::app::Clusters;
using chip::Protocols::InteractionModel::Status;

namespace {

constexpr EndpointId kCoveringEndpoint = 1;

atomic_t s_move_count;
atomic_t s_stall_count;

/*
 * Position attributes are nullable: null means the covering does not know
 * where it is. That is a meaningful state rather than an error, so it is
 * reported as UINT16_MAX instead of being coerced to 0.
 */
uint16_t ReadPercent100ths(
	Status (*getter)(EndpointId, app::DataModel::Nullable<Percent100ths> &))
{
	app::DataModel::Nullable<Percent100ths> value;

	if (getter(kCoveringEndpoint, value) != Status::Success || value.IsNull()) {
		return UINT16_MAX;
	}

	return value.Value();
}

blinds_motion_t DecodeMotion(uint8_t status, uint8_t shift)
{
	/* OperationalStatus packs global/lift/tilt into 2-bit fields. */
	switch ((status >> shift) & 0x03) {
	case 1:
		return BLINDS_MOTION_OPENING;
	case 2:
		return BLINDS_MOTION_CLOSING;
	default:
		return BLINDS_MOTION_STALLED;
	}
}

} /* namespace */

void blinds_get_data(struct blinds_data *out)
{
	if (out == nullptr) {
		return;
	}

	*out = {};
	out->lift_position = UINT16_MAX;
	out->tilt_position = UINT16_MAX;
	out->lift_target = UINT16_MAX;
	out->tilt_target = UINT16_MAX;

	DeviceLayer::PlatformMgr().LockChipStack();

	out->lift_position =
		ReadPercent100ths(WindowCovering::Attributes::CurrentPositionLiftPercent100ths::Get);
	out->tilt_position =
		ReadPercent100ths(WindowCovering::Attributes::CurrentPositionTiltPercent100ths::Get);
	out->lift_target =
		ReadPercent100ths(WindowCovering::Attributes::TargetPositionLiftPercent100ths::Get);
	out->tilt_target =
		ReadPercent100ths(WindowCovering::Attributes::TargetPositionTiltPercent100ths::Get);

	BitMask<WindowCovering::OperationalStatus> status;
	if (WindowCovering::Attributes::OperationalStatus::Get(kCoveringEndpoint, &status) ==
	    Status::Success) {
		out->lift_motion = DecodeMotion(status.Raw(), 2);
		out->tilt_motion = DecodeMotion(status.Raw(), 4);
	}

	BitMask<WindowCovering::ConfigStatus> config;
	if (WindowCovering::Attributes::ConfigStatus::Get(kCoveringEndpoint, &config) ==
	    Status::Success) {
		out->config_status = config.Raw();
		/* LiftPositionAware — set once the covering knows where it is. A
		 * unit that loses calibration in the field becomes a support
		 * call, so it is worth reporting on every heartbeat. */
		out->calibrated =
			config.Has(WindowCovering::ConfigStatus::kLiftPositionAware);
	}

	BitMask<WindowCovering::Mode> mode;
	if (WindowCovering::Attributes::Mode::Get(kCoveringEndpoint, &mode) == Status::Success) {
		out->mode = mode.Raw();
	}

	DeviceLayer::PlatformMgr().UnlockChipStack();
}

uint32_t blinds_take_move_count(void)
{
	return (uint32_t)atomic_set(&s_move_count, 0);
}

uint32_t blinds_take_stall_count(void)
{
	return (uint32_t)atomic_set(&s_stall_count, 0);
}

void blinds_record_move_start(void)
{
	atomic_inc(&s_move_count);
}

void blinds_record_stall(void)
{
	atomic_inc(&s_stall_count);
}
