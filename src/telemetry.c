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
#include "telemetry.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "matter_metrics.h"
#ifdef CONFIG_BLINDS_THREAD_AUTOJOIN
#include "thread_prov.h"
#endif
#include "blinds.h"
#include "border_router.h"
#ifdef CONFIG_BLINDS_SIM
#include "blinds_sim.h"
#endif

#ifdef CONFIG_PROVISIONING
#include "provisioning.h"
#endif

#include <openthread.h>
#include <openthread/link.h>
#include <openthread/thread.h>
#include <openthread/srp_client.h>
#include <openthread/nat64.h>
#include <openthread/dataset.h>

#ifdef CONFIG_MEMFAULT
#include <memfault/core/data_packetizer.h>
#include <memfault/metrics/metrics.h>
#include <memfault/core/trace_event.h>
#endif

LOG_MODULE_REGISTER(telemetry, LOG_LEVEL_INF);

#define UPLOAD_INTERVAL_SEC  (5 * 60)   /* 5 minutes between uploads */
#define RETRY_INTERVAL_SEC   60         /* retry on failure */
#define POLL_INTERVAL_SEC    5          /* Thread attach polling */
#define STARTUP_DELAY_SEC    10         /* let the system settle */

/*
 * Data poll period held while a cloud transaction is in flight.
 *
 * In Matter idle mode this device polls every 19 s, which is correct for a
 * shade — nobody needs sub-second response from a window covering. But every
 * inbound packet then waits up to a poll period, so a DNS lookup or a CoAP
 * response is delayed by that much. Measured on hardware: nRF Cloud's reply to
 * POST /auth/jwt consistently arrived 19.1 s after the request, which looked
 * like server latency and was in fact our own duty cycle. SNTP failed outright
 * whenever no poll landed inside its timeout.
 *
 * So poll fast for the seconds an upload takes, then go straight back to idle.
 * The energy argument is that the fast window is bounded and infrequent: a few
 * seconds per upload against a 300 s heartbeat, instead of permanently
 * shortening the poll period and paying for it continuously.
 */
#define FAST_POLL_MS         500

/* Memfault chunk proxy URL prefix */
#define MEMFAULT_CHUNKS_URL \
	"https://chunks.memfault.com/api/v0/chunks/" DEVICE_ID

/*
 * Posted by the button handler (and anything else wanting an immediate
 * upload). The telemetry thread waits on this instead of sleeping flat out,
 * so a demo gets a chunk in seconds rather than up to UPLOAD_INTERVAL_SEC.
 */
static K_SEM_DEFINE(s_upload_now, 0, 1);

void telemetry_request_upload(void)
{
	k_sem_give(&s_upload_now);
}

/* Filled in by the transport so upload cost can be reported per heartbeat. */
struct telemetry_timing telemetry_timing;

/*
 * Enter/leave the fast-poll window. Zero clears the override and returns the
 * device to whatever Matter's ICD management has configured, rather than
 * pinning a value we guessed.
 */
static void set_fast_poll(bool fast)
{
	otInstance *instance = openthread_get_default_instance();

	if (instance == NULL) {
		return;
	}

	openthread_mutex_lock();
	otLinkSetPollPeriod(instance, fast ? FAST_POLL_MS : 0);
	openthread_mutex_unlock();
}

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

#ifdef CONFIG_BLINDS_SIM
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_motor_current_ma),
		blinds_sim_motor_current_ma());
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_travel_pct_total),
		blinds_sim_take_travel_pct());
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(blinds_obstructions),
		blinds_sim_take_obstructions());
#endif
}

static struct {
	/* MAC counters */
	uint32_t tx_total;
	uint32_t tx_retry;
	uint32_t tx_err_cca;
	uint32_t tx_err_abort;
	uint32_t rx_err_fcs;
	uint32_t rx_err_sec;
	uint32_t rx_total;
	uint32_t tx_acked;
	uint32_t tx_err_busy;
	uint32_t rx_duplicated;
	uint32_t rx_err_no_frame;
	uint32_t ip6_tx_fail;
	uint32_t ip6_rx_fail;
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

/*
 * Set by the telemetry thread. time_sync_ok was defined from the start but
 * never written, so the metric has been reporting zero for every device that
 * has ever run this firmware.
 */
static uint32_t s_time_sync_ok;
static uint32_t s_sntp_sync_ms;
static uint32_t s_sntp_attempts;

/* Previous role/parent, so transitions can be raised as trace events. */
static otDeviceRole s_prev_role = OT_DEVICE_ROLE_DISABLED;
static uint16_t s_prev_parent_rloc;

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

	/* --- Sleepy-device radio duty cycle --- */

	/*
	 * Poll period dominates radio-on time for an SSED, so it is the nearest
	 * thing to an energy figure available without a power monitor.
	 */
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_poll_period_ms), otLinkGetPollPeriod(instance));

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_child_timeout_s), otThreadGetChildTimeout(instance));
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_rloc16), otThreadGetRloc16(instance));

	/* --- Remaining MAC counter deltas --- */

	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_rx_total),
		mac->mRxTotal - s_prev_counters.rx_total);
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_tx_acked),
		mac->mTxAcked - s_prev_counters.tx_acked);
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_tx_err_busy),
		mac->mTxErrBusyChannel - s_prev_counters.tx_err_busy);
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_rx_duplicated),
		mac->mRxDuplicated - s_prev_counters.rx_duplicated);
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_rx_err_no_frame),
		mac->mRxErrNoFrame - s_prev_counters.rx_err_no_frame);

	s_prev_counters.rx_total = mac->mRxTotal;
	s_prev_counters.tx_acked = mac->mTxAcked;
	s_prev_counters.tx_err_busy = mac->mTxErrBusyChannel;
	s_prev_counters.rx_duplicated = mac->mRxDuplicated;
	s_prev_counters.rx_err_no_frame = mac->mRxErrNoFrame;

	/*
	 * IPv6 counters separate "the radio is fine but routing is broken" from
	 * "the RF environment is bad" — two failure modes with the same symptom.
	 */
	const otIpCounters *ip = otThreadGetIp6Counters(instance);

	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_ip6_tx_fail),
		ip->mTxFailure - s_prev_counters.ip6_tx_fail);
	memfault_metrics_heartbeat_set_unsigned(MEMFAULT_METRICS_KEY(ot_ip6_rx_fail),
		ip->mRxFailure - s_prev_counters.ip6_rx_fail);
	s_prev_counters.ip6_tx_fail = ip->mTxFailure;
	s_prev_counters.ip6_rx_fail = ip->mRxFailure;

	/*
	 * SRP registration. A device on Thread but not SRP-registered is
	 * reachable by us and invisible to the ecosystem — no other symptom.
	 */
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_srp_registered),
		otSrpClientIsRunning(instance) ? 1 : 0);

	/*
	 * NAT64 capability of the gateway, probed rather than assumed: synthesis
	 * fails when the border router publishes no prefix. This is Warema's
	 * gateway-compatibility question as a fleet metric.
	 */
	otIp4Address probe = { .mFields.m8 = { 8, 8, 8, 8 } };
	otIp6Address synth;
	bool nat64 = (otNat64SynthesizeIp6Address(instance, &probe, &synth) ==
		      OT_ERROR_NONE);

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_nat64_available), nat64 ? 1 : 0);

	/* Network name — weaker than the vendor TLV, but free. */
	const char *netname = otThreadGetNetworkName(instance);

	openthread_mutex_unlock();

	if (netname != NULL) {
		memfault_metrics_heartbeat_set_string(
			MEMFAULT_METRICS_KEY(ot_network_name), netname);
	}

	/* --- Border router identity (answered by the gateway itself) --- */

	struct border_router_info br;

	border_router_get(&br);

	if (br.valid) {
		memfault_metrics_heartbeat_set_string(
			MEMFAULT_METRICS_KEY(ot_br_vendor_name), br.vendor_name);
		memfault_metrics_heartbeat_set_string(
			MEMFAULT_METRICS_KEY(ot_br_vendor_model), br.vendor_model);
	}
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(ot_br_query_failures), br.query_failures);
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
/*
 * Upload cost and time-sync health.
 *
 * nrfcloud_auth_ms exists because nRF Cloud's response to POST /auth/jwt was
 * observed at a consistent 19.1 s. Measuring it per device turns one lab
 * observation into a number we can hold the product team to.
 */
static void collect_plumbing_metrics(void)
{
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(time_sync_ok), s_time_sync_ok);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(sntp_sync_ms), s_sntp_sync_ms);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(sntp_attempts), s_sntp_attempts);
	s_sntp_attempts = 0;

	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(nrfcloud_handshake_ms),
		telemetry_timing.handshake_ms);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(nrfcloud_auth_ms), telemetry_timing.auth_ms);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(nrfcloud_connect_ms),
		telemetry_timing.connect_ms);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(nrfcloud_chunks_sent),
		telemetry_timing.chunks_sent);
	memfault_metrics_heartbeat_set_unsigned(
		MEMFAULT_METRICS_KEY(nrfcloud_bytes_sent),
		telemetry_timing.bytes_sent);

	/* Deltas: each heartbeat reports its own interval. */
	telemetry_timing.chunks_sent = 0;
	telemetry_timing.bytes_sent = 0;
}

void memfault_metrics_heartbeat_collect_data(void)
{
	memfault_ncs_metrics_collect_data();
	collect_ot_metrics();
	collect_blinds_metrics();
	collect_plumbing_metrics();
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
			MEMFAULT_TRACE_EVENT_WITH_LOG(nrfcloud_chunk_rejected,
				"CoAP %d.%02d", code / 100, code % 100);
			memfault_packetizer_abort();
			telemetry_record_upload_err();
			return -EIO;
		}

		chunks_sent++;
		telemetry_timing.chunks_sent++;
		telemetry_timing.bytes_sent += (uint32_t)pkt_len;
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
			int64_t t0 = k_uptime_get();

			/* DNS + SNTP are both request/response: without this
			 * they wait a full poll period per exchange. */
			set_fast_poll(true);

			for (int i = 0; i < 3; i++) {
				s_sntp_attempts++;
				if (sntp_sync(NULL) == 0) {
					synced = true;
					break;
				}
				k_sleep(K_SECONDS(5));
			}

			set_fast_poll(false);

			s_sntp_sync_ms = (uint32_t)(k_uptime_get() - t0);
			s_time_sync_ok = synced ? 1 : 0;

			if (!synced) {
				LOG_WRN("SNTP sync failed, retrying later");
#ifdef CONFIG_MEMFAULT
				/* Time sync gates JWT signing, so this is an
				 * auth outage, not a cosmetic failure. */
				MEMFAULT_TRACE_EVENT_WITH_LOG(sntp_failed,
					"%u attempts over %u ms",
					(unsigned)s_sntp_attempts,
					(unsigned)s_sntp_sync_ms);
#endif
				k_sleep(K_SECONDS(RETRY_INTERVAL_SEC));
				continue;
			}

			/*
			 * Newly attached and time is good: ask the gateway who
			 * made it. Once per attach, not per heartbeat.
			 */
			border_router_query();
		}

#ifdef CONFIG_MEMFAULT
		/* Only connect if there's data to send */
		if (!memfault_packetizer_data_available()) {
			k_sem_take(&s_upload_now, K_SECONDS(UPLOAD_INTERVAL_SEC));
			continue;
		}

		struct nrfcloud_session s;

		set_fast_poll(true);

		if (nrfcloud_connect(&s) == 0) {
			drain_memfault_chunks(&s);
			nrfcloud_disconnect(&s);
			set_fast_poll(false);
			/*
			 * Interruptible wait: a button press (or anything else
			 * calling telemetry_request_upload) cuts the interval
			 * short instead of leaving a demo staring at a console.
			 */
			k_sem_take(&s_upload_now, K_SECONDS(UPLOAD_INTERVAL_SEC));
		} else {
			set_fast_poll(false);
			telemetry_record_upload_err();
			LOG_WRN("nRF Cloud connect failed, retrying later");
			k_sem_take(&s_upload_now, K_SECONDS(RETRY_INTERVAL_SEC));
		}
#else
		k_sleep(K_SECONDS(UPLOAD_INTERVAL_SEC));
#endif
	}
}

K_THREAD_DEFINE(telemetry_tid, 8192, telemetry_thread,
		NULL, NULL, NULL, K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);
