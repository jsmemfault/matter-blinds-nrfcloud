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
 * Simulated shade behaviour, so the product metrics carry a realistic signal
 * on a devkit with no motor attached.
 *
 * It drives the real Matter WindowCovering cluster rather than writing metrics
 * directly: commands go through the same path a controller would use, so
 * blinds.cpp keeps reading live attributes and what Memfault reports is still
 * exactly what a Matter controller would see. Deleting this file changes
 * nothing else.
 */

/* Motor current for the most recent sample, mA. 0 when stalled/idle. */
uint32_t blinds_sim_motor_current_ma(void);

/* Cumulative travel in percent of full range, reset on read. */
uint32_t blinds_sim_take_travel_pct(void);

/* Obstruction trips, reset on read. */
uint32_t blinds_sim_take_obstructions(void);

#ifdef __cplusplus
}
#endif
