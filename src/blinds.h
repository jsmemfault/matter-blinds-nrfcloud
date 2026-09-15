/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Observability view of the window covering.
 *
 * Values are read from the live Matter WindowCovering cluster attributes
 * rather than from a simulation, so what Memfault reports is exactly what a
 * Matter controller sees. On a real product this file is the only thing that
 * changes when the motor driver replaces the sample's PWM indicators.
 */

/* Mirrors Matter OperationalStatus movement bits. */
typedef enum {
	BLINDS_MOTION_STALLED = 0,
	BLINDS_MOTION_OPENING = 1,
	BLINDS_MOTION_CLOSING = 2,
} blinds_motion_t;

struct blinds_data {
	/* Positions in hundredths of a percent (0 = open, 10000 = closed).
	 * UINT16_MAX means the attribute is null / position unknown. */
	uint16_t        lift_position;
	uint16_t        tilt_position;
	uint16_t        lift_target;
	uint16_t        tilt_target;

	blinds_motion_t lift_motion;
	blinds_motion_t tilt_motion;

	bool            calibrated;
	uint8_t         mode;           /* Matter Mode attribute bitmap */
	uint8_t         config_status;  /* Matter ConfigStatus bitmap */
};

/* Snapshot current covering state. Takes the CHIP stack lock internally. */
void blinds_get_data(struct blinds_data *out);

/* Cumulative movement counters, reset on read (heartbeat deltas). */
uint32_t blinds_take_move_count(void);
uint32_t blinds_take_stall_count(void);

/* Called from the window covering driver on state transitions. */
void blinds_record_move_start(void);
void blinds_record_stall(void);

#ifdef __cplusplus
}
#endif
