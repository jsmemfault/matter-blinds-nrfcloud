/*
 * Automatic Memfault telemetry upload over nRF Cloud.
 *
 * A dedicated thread that waits for Thread network attachment, syncs time
 * via SNTP, then periodically connects to nRF Cloud and drains pending
 * Memfault chunks (heartbeat metrics, coredumps, events).
 */

#include "dtls_transport.h"
#include "coap_codec.h"
#include "credentials.h"
#include "jwt.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "matter_metrics.h"
#ifdef CONFIG_BLINDS_THREAD_AUTOJOIN
#include "thread_prov.h"
#endif
#include "blinds.h"

#ifdef CONFIG_PROVISIONING
#include "provisioning.h"
#endif

#include <openthread.h>
#include <openthread/link.h>
#include <openthread/thread.h>

#ifdef CONFIG_MEMFAULT
#include <memfault/core/data_packetizer.h>
#include <memfault/metrics/metrics.h>
#endif

LOG_MODULE_REGISTER(telemetry, LOG_LEVEL_INF);

#define UPLOAD_INTERVAL_SEC  (5 * 60)   /* 5 minutes between uploads */
#define RETRY_INTERVAL_SEC   60         /* retry on failure */
#define POLL_INTERVAL_SEC    5          /* Thread attach polling */
#define STARTUP_DELAY_SEC    10         /* let the system settle */

/* Memfault chunk proxy URL prefix */
#define MEMFAULT_CHUNKS_URL \
	"https://chunks.memfault.com/api/v0/chunks/" DEVICE_ID

static bool is_thread_attached(void)
{
	otInstance *instance = openthread_get_default_instance();

	if (!instance) {
		return false;
	}

	openthread_mutex_lock();
	otDeviceRole role = otThreadGetDeviceRole(instance);
	openthread_mutex_unlock();

	return role >= OT_DEVICE_ROLE_CHILD;
}

#ifdef CONFIG_MEMFAULT

/* --- Heartbeat metric collection --- */

/* Chain to NCS default metrics (stack usage, CPU, thermal, etc.) */
extern void memfault_ncs_metrics_collect_data(void);

static void collect_blinds_metrics(void)
{
	struct blinds_data d;

	blinds_get_data(&d);

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_lift_position), d.lift_position);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_tilt_position), d.tilt_position);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_lift_motion), (uint32_t)d.lift_motion);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_tilt_motion), (uint32_t)d.tilt_motion);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_calibrated), d.calibrated ? 1 : 0);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_config_status), d.config_status);

	/* Deltas — reset on read so each heartbeat reports its own interval. */
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_moves), blinds_take_move_count());
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_stalls), blinds_take_stall_count());
}

static struct {
	/* MAC counters */
	uint32_t tx_total;
	uint32_t tx_retry;
	uint32_t tx_err_cca;
	uint32_t tx_err_abort;
	uint32_t rx_err_fcs;
	uint32_t rx_err_sec;
	/* MLE event counters */
	uint16_t attach_attempts;
	uint16_t parent_changes;
	uint16_t partition_changes;
	/* MLE time-in-role (ms, 64-bit to avoid overflow) */
	uint64_t detached_ms;
	uint64_t child_ms;
	uint64_t router_ms;
	uint64_t leader_ms;
} s_prev_counters;

static void collect_ot_metrics(void)
{
	otInstance *instance = openthread_get_default_instance();

	if (!instance) {
		return;
	}

	openthread_mutex_lock();

	/* Thread role (0=disabled, 1=detached, 2=child, 3=router, 4=leader) */
	otDeviceRole role = otThreadGetDeviceRole(instance);

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_role), (uint32_t)role);

	/* Parent RSSI */
	int8_t parent_rssi;

	if (otThreadGetParentAverageRssi(instance, &parent_rssi) == OT_ERROR_NONE) {
		memfault_metrics_heartbeat_set_signed(
			MEMFAULT_METRICS_KEY(ot_parent_rssi),
			parent_rssi);
	}

	/* MAC counters (deltas since last heartbeat) */
	const otMacCounters *mac = otLinkGetCounters(instance);

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_tx_total),
		mac->mTxTotal - s_prev_counters.tx_total);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_tx_retry),
		mac->mTxRetry - s_prev_counters.tx_retry);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_tx_err_cca),
		mac->mTxErrCca - s_prev_counters.tx_err_cca);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_rx_err_fcs),
		mac->mRxErrFcs - s_prev_counters.rx_err_fcs);

	s_prev_counters.tx_total = mac->mTxTotal;
	s_prev_counters.tx_retry = mac->mTxRetry;
	s_prev_counters.tx_err_cca = mac->mTxErrCca;
	s_prev_counters.rx_err_fcs = mac->mRxErrFcs;

	/* Additional MAC counter deltas */
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_tx_err_abort),
		mac->mTxErrAbort - s_prev_counters.tx_err_abort);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_rx_err_sec),
		mac->mRxErrSec - s_prev_counters.rx_err_sec);
	s_prev_counters.tx_err_abort = mac->mTxErrAbort;
	s_prev_counters.rx_err_sec = mac->mRxErrSec;

	/* MLE counters (deltas) */
	const otMleCounters *mle = otThreadGetMleCounters(instance);

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_attach_attempts),
		mle->mAttachAttempts - s_prev_counters.attach_attempts);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_parent_changes),
		mle->mParentChanges - s_prev_counters.parent_changes);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_partition_changes),
		mle->mPartitionIdChanges - s_prev_counters.partition_changes);
	s_prev_counters.attach_attempts = mle->mAttachAttempts;
	s_prev_counters.parent_changes = mle->mParentChanges;
	s_prev_counters.partition_changes = mle->mPartitionIdChanges;

	/* Time-in-role deltas (ms) */
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_detached_ms),
		(uint32_t)(mle->mDetachedTime - s_prev_counters.detached_ms));
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_child_ms),
		(uint32_t)(mle->mChildTime - s_prev_counters.child_ms));
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_router_ms),
		(uint32_t)(mle->mRouterTime - s_prev_counters.router_ms));
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_leader_ms),
		(uint32_t)(mle->mLeaderTime - s_prev_counters.leader_ms));
	s_prev_counters.detached_ms = mle->mDetachedTime;
	s_prev_counters.child_ms = mle->mChildTime;
	s_prev_counters.router_ms = mle->mRouterTime;
	s_prev_counters.leader_ms = mle->mLeaderTime;

	/* Channel snapshot */
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_channel), otLinkGetChannel(instance));

	/* Neighbor count */
	uint8_t neighbor_count = 0;
	otNeighborInfoIterator iter = OT_NEIGHBOR_INFO_ITERATOR_INIT;
	otNeighborInfo neighbor_info;

	while (otThreadGetNextNeighborInfo(instance, &iter, &neighbor_info) == OT_ERROR_NONE) {
		neighbor_count++;
	}
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_neighbor_count), neighbor_count);

	/*
	 * Router count.
	 *
	 * otThreadGetRouterInfo() is FTD-only — it is absent from the prebuilt
	 * MTD library, so this cannot be compiled on a sleepy end device. A
	 * shade is an MTD, and an MTD has no view of the router table anyway:
	 * it sees exactly one parent. The parent-based metrics below carry the
	 * useful signal in that topology.
	 */
	uint8_t router_count = 0;

#ifdef CONFIG_OPENTHREAD_FTD
	for (uint8_t i = 0; i < 64; i++) {
		otRouterInfo router_info;

		if (otThreadGetRouterInfo(instance, i, &router_info) == OT_ERROR_NONE &&
		    router_info.mAllocated) {
			router_count++;
		}
	}
#endif
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_router_count), router_count);

	/* Link quality from parent */
	otRouterInfo parent_info;

	if (otThreadGetParentInfo(instance, &parent_info) == OT_ERROR_NONE) {
		memfault_metrics_heartbeat_set_unsigned(
			MEMFAULT_METRICS_KEY(ot_link_quality), parent_info.mLinkQualityIn);
	}

	openthread_mutex_unlock();
}

/* Track upload errors */
void telemetry_record_upload_err(void)
{
	memfault_metrics_heartbeat_add(
		MEMFAULT_METRICS_KEY(nrfcloud_upload_err), 1);
}

#ifdef CONFIG_PROVISIONING
/*
 * Days until the device identity certificate expires.
 *
 * A shade outlives its certificates. Reporting this per device turns a
 * fleet-wide expiry — which otherwise surfaces as every unit going silent on
 * the same day, years from now — into an alert you can set today.
 */
static void collect_identity_metrics(void)
{
	uint32_t not_after = provisioning_cert_not_after();
	uint32_t now = get_current_time();
	uint32_t days = 0;

	if (not_after != 0 && now != 0 && not_after > now) {
		days = (not_after - now) / 86400;
	}

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(identity_cert_days_left), days);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(identity_state),
		(uint32_t)provisioning_get_state());
}
#endif

/* Called by Memfault SDK before each heartbeat snapshot */
void memfault_metrics_heartbeat_collect_data(void)
{
	memfault_ncs_metrics_collect_data();
	collect_ot_metrics();
	collect_blinds_metrics();
	matter_metrics_collect();
#ifdef CONFIG_PROVISIONING
	collect_identity_metrics();
#endif
}

static int coap_build_proxy_header(uint8_t *buf, size_t buf_size,
				   uint8_t *token_out)
{
	int pos;
	uint16_t prev_opt = 0;
	const char *proxy_uri = MEMFAULT_CHUNKS_URL;
	const char *project_key = CONFIG_MEMFAULT_NCS_PROJECT_KEY;
	uint8_t token = coap_random_token();

	if (token_out) {
		*token_out = token;
	}

	pos = coap_start_request(buf, buf_size, COAP_CODE_POST, token);
	if (pos < 0) {
		return pos;
	}

	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_URI_PATH, "proxy", 5);
	if (pos < 0) {
		return pos;
	}

	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_PROXY_URI, proxy_uri,
				 strlen(proxy_uri));
	if (pos < 0) {
		return pos;
	}

	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_MEMFAULT_KEY, project_key,
				 strlen(project_key));
	if (pos < 0) {
		return pos;
	}

	if ((size_t)pos + 1 > buf_size) {
		return -ENOMEM;
	}
	buf[pos++] = 0xFF;

	return pos;
}

static int drain_memfault_chunks(struct nrfcloud_session *s)
{
	static uint8_t pkt_buf[512];
	int chunks_sent = 0;

	while (true) {
		uint8_t token;
		int hdr_len = coap_build_proxy_header(pkt_buf, sizeof(pkt_buf),
						      &token);
		if (hdr_len < 0) {
			LOG_ERR("CoAP proxy header build failed");
			break;
		}

		size_t chunk_len = sizeof(pkt_buf) - (size_t)hdr_len;
		bool has_data = memfault_packetizer_get_chunk(
			pkt_buf + hdr_len, &chunk_len);

		if (!has_data) {
			break;
		}

		int pkt_len = hdr_len + (int)chunk_len;
		int ret = nrfcloud_send(s, pkt_buf, pkt_len);

		if (ret < 0) {
			LOG_ERR("Chunk send failed: -0x%04x", -ret);
			memfault_packetizer_abort();
			telemetry_record_upload_err();
			return ret;
		}

		ret = nrfcloud_recv(s, pkt_buf, sizeof(pkt_buf));
		if (ret < 0) {
			LOG_ERR("Chunk recv failed: -0x%04x", -ret);
			memfault_packetizer_abort();
			telemetry_record_upload_err();
			return ret;
		}

		int code = coap_parse_response(pkt_buf, ret);

		if (code != 201) {
			LOG_ERR("Chunk upload rejected: %d.%02d",
				code / 100, code % 100);
			memfault_packetizer_abort();
			telemetry_record_upload_err();
			return -EIO;
		}

		chunks_sent++;
	}

	if (chunks_sent > 0) {
		LOG_INF("Uploaded %d Memfault chunk(s)", chunks_sent);
	}

	return 0;
}

#endif /* CONFIG_MEMFAULT */

static void telemetry_thread(void *p1, void *p2, void *p3)
{
	k_sleep(K_SECONDS(STARTUP_DELAY_SEC));
	LOG_INF("Telemetry thread started");

#ifdef CONFIG_BLINDS_THREAD_AUTOJOIN
	/* Developer path: join a known Thread network without BLE commissioning */
	thread_prov_auto_join();
#endif

	while (true) {
		/* Wait for Thread network */
		while (!is_thread_attached()) {
			k_sleep(K_SECONDS(POLL_INTERVAL_SEC));
		}

		/* Sync time if needed */
		if (get_current_time() == 0) {
			bool synced = false;

			for (int i = 0; i < 3; i++) {
				if (sntp_sync(NULL) == 0) {
					synced = true;
					break;
				}
				k_sleep(K_SECONDS(5));
			}
			if (!synced) {
				LOG_WRN("SNTP sync failed, retrying later");
				k_sleep(K_SECONDS(RETRY_INTERVAL_SEC));
				continue;
			}
		}

#ifdef CONFIG_MEMFAULT
		/* Only connect if there's data to send */
		if (!memfault_packetizer_data_available()) {
			k_sleep(K_SECONDS(UPLOAD_INTERVAL_SEC));
			continue;
		}

		struct nrfcloud_session s;

		if (nrfcloud_connect(&s) == 0) {
			drain_memfault_chunks(&s);
			nrfcloud_disconnect(&s);
			k_sleep(K_SECONDS(UPLOAD_INTERVAL_SEC));
		} else {
			telemetry_record_upload_err();
			LOG_WRN("nRF Cloud connect failed, retrying later");
			k_sleep(K_SECONDS(RETRY_INTERVAL_SEC));
		}
#else
		k_sleep(K_SECONDS(UPLOAD_INTERVAL_SEC));
#endif
	}
}

K_THREAD_DEFINE(telemetry_tid, 8192, telemetry_thread,
		NULL, NULL, NULL, K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);
