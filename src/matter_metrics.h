/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void matter_metrics_init(void);
void matter_metrics_collect(void);

/* Call from Matter stack callbacks to record events */
void matter_metrics_record_case_failure(void);
void matter_metrics_record_subscription_teardown(void);

#ifdef __cplusplus
}
#endif
