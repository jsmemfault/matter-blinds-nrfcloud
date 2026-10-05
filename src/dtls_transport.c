/*
 * DTLS transport over OpenThread native UDP.
 *
 * Provides connect/disconnect/send/recv for nRF Cloud CoAP.
 * Shell commands are in nrfcloud_shell.c.
 */

#include "dtls_transport.h"
#include "coap_codec.h"
#include "credentials.h"
#include "jwt.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <openthread.h>
#include <openthread/udp.h>
#include <openthread/dns_client.h>
#include <openthread/ip6.h>
#include <openthread/message.h>
#include <openthread/nat64.h>
#include <openthread/thread.h>

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <zephyr/random/random.h>

#include <string.h>

LOG_MODULE_REGISTER(dtls_transport, LOG_LEVEL_INF);

#define COAP_SERVER_HOST "coap.nrfcloud.com"
#define COAP_SERVER_PORT 5684

/* Fallback IPv4 for coap.nrfcloud.com — used when DNS64 is unavailable */
#define COAP_SERVER_FALLBACK_IPV4 "34.200.153.177"

#define RX_BUF_SIZE    1280  /* must fit a full Block2 response + DTLS overhead */
#define RX_QUEUE_DEPTH 4

/* --- Received datagram (queued from OT callback -> consumed by BIO recv) --- */

struct rx_pkt {
	uint8_t data[RX_BUF_SIZE];
	uint16_t len;
};

K_MSGQ_DEFINE(rx_msgq, sizeof(struct rx_pkt), RX_QUEUE_DEPTH, 4);

/* Serialize access — only one DTLS session at a time.
 * Callers must hold this around their full connect → send/recv → disconnect sequence. */
K_MUTEX_DEFINE(nrfcloud_mutex);

/* --- DTLS timer callbacks --- */

static void dtls_timer_set(void *ctx, uint32_t int_ms, uint32_t fin_ms)
{
	struct nrfcloud_session *s = ctx;

	s->timer.start = k_uptime_get();
	s->timer.int_ms = int_ms;
	s->timer.fin_ms = fin_ms;
}

static int dtls_timer_get(void *ctx)
{
	struct nrfcloud_session *s = ctx;

	if (s->timer.fin_ms == 0) {
		return -1;
	}
	int64_t elapsed = k_uptime_get() - s->timer.start;

	if (elapsed >= s->timer.fin_ms) {
		return 2;
	}
	if (elapsed >= s->timer.int_ms) {
		return 1;
	}
	return 0;
}

/* --- OT UDP receive callback (runs in OT thread context) --- */

static void ot_udp_recv_cb(void *aContext, otMessage *aMessage,
			    const otMessageInfo *aMessageInfo)
{
	struct rx_pkt pkt;
	uint16_t offset = otMessageGetOffset(aMessage);
	uint16_t length = otMessageGetLength(aMessage) - offset;

	if (length > RX_BUF_SIZE) {
		length = RX_BUF_SIZE;
	}
	pkt.len = otMessageRead(aMessage, offset, pkt.data, length);

	if (k_msgq_put(&rx_msgq, &pkt, K_NO_WAIT) != 0) {
		LOG_WRN("RX queue full, dropping datagram");
	}
}

/* --- mbedTLS BIO send callback --- */

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct nrfcloud_session *s = ctx;
	otInstance *instance = s->bio.instance;
	otMessageInfo info;

	openthread_mutex_lock();

	otMessage *msg = otUdpNewMessage(instance, NULL);

	if (!msg) {
		openthread_mutex_unlock();
		return MBEDTLS_ERR_SSL_ALLOC_FAILED;
	}

	otError err = otMessageAppend(msg, buf, (uint16_t)len);

	if (err != OT_ERROR_NONE) {
		otMessageFree(msg);
		openthread_mutex_unlock();
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
	}

	memset(&info, 0, sizeof(info));
	info.mPeerAddr = s->bio.peer_addr;
	info.mPeerPort = s->bio.peer_port;

	err = otUdpSend(instance, &s->bio.socket, msg, &info);
	openthread_mutex_unlock();

	if (err != OT_ERROR_NONE) {
		LOG_ERR("otUdpSend failed: %d", err);
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
	}

	LOG_DBG("DTLS tx: %u bytes", (unsigned)len);
	return (int)len;
}

/* --- mbedTLS BIO recv callback with timeout --- */

static int bio_recv_timeout(void *ctx, unsigned char *buf, size_t len,
			    uint32_t timeout)
{
	struct rx_pkt pkt;

	int ret = k_msgq_get(&rx_msgq, &pkt, K_MSEC(timeout ? timeout : 30000));

	if (ret != 0) {
		return MBEDTLS_ERR_SSL_TIMEOUT;
	}

	int n = (pkt.len < (uint16_t)len) ? pkt.len : (uint16_t)len;

	memcpy(buf, pkt.data, n);
	LOG_DBG("DTLS rx: %u bytes", (unsigned)n);
	return n;
}

/* --- RNG wrapper for mbedTLS ---
 * Only needed when mbedTLS is not drawing randomness from PSA (see the
 * mbedtls_ssl_conf_rng() call below).
 */

#if !defined(MBEDTLS_USE_PSA_CRYPTO)
static int dtls_rng(void *ctx, unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);
	return sys_csrand_get(buf, len) == 0 ? 0 : -1;
}
#endif

/* --- DNS resolution --- */

static K_SEM_DEFINE(dtls_dns_sem, 0, 1);
static otIp6Address dtls_resolved_addr;
static bool dtls_dns_ok;

static void dtls_dns_cb(otError aError, const otDnsAddressResponse *aResponse,
			void *aContext)
{
	if (aError != OT_ERROR_NONE) {
		dtls_dns_ok = false;
		k_sem_give(&dtls_dns_sem);
		return;
	}

	uint32_t ttl;

	dtls_dns_ok = (otDnsAddressResponseGetAddress(aResponse, 0,
			&dtls_resolved_addr, &ttl) == OT_ERROR_NONE);
	k_sem_give(&dtls_dns_sem);
}

static bool resolve_server(otInstance *instance, otIp6Address *addr)
{
	otError err;

	LOG_INF("Resolving %s ...", COAP_SERVER_HOST);
	k_sem_reset(&dtls_dns_sem);
	dtls_dns_ok = false;

	openthread_mutex_lock();
	err = otDnsClientResolveIp4Address(instance, COAP_SERVER_HOST,
					   dtls_dns_cb, NULL, NULL);
	openthread_mutex_unlock();

	if (err == OT_ERROR_NONE &&
	    k_sem_take(&dtls_dns_sem, K_SECONDS(10)) == 0 && dtls_dns_ok) {
		*addr = dtls_resolved_addr;
		return true;
	}

	k_sem_reset(&dtls_dns_sem);
	dtls_dns_ok = false;

	openthread_mutex_lock();
	err = otDnsClientResolveAddress(instance, COAP_SERVER_HOST,
					dtls_dns_cb, NULL, NULL);
	openthread_mutex_unlock();

	if (err == OT_ERROR_NONE &&
	    k_sem_take(&dtls_dns_sem, K_SECONDS(10)) == 0 && dtls_dns_ok) {
		*addr = dtls_resolved_addr;
		return true;
	}

	/* DNS64 unavailable — synthesize NAT64 address from hardcoded IPv4 */
	LOG_WRN("DNS failed, synthesizing NAT64 from %s", COAP_SERVER_FALLBACK_IPV4);
	otIp4Address ipv4;

	if (otIp4AddressFromString(COAP_SERVER_FALLBACK_IPV4, &ipv4) != OT_ERROR_NONE) {
		return false;
	}

	openthread_mutex_lock();
	err = otNat64SynthesizeIp6Address(instance, &ipv4, addr);
	openthread_mutex_unlock();

	return (err == OT_ERROR_NONE);
}

/* --- Public API --- */

uint8_t coap_random_token(void)
{
	uint8_t token;

	sys_csrand_get(&token, 1);
	return token;
}

int nrfcloud_connect(struct nrfcloud_session *s)
{
	k_mutex_lock(&nrfcloud_mutex, K_FOREVER);

	otInstance *instance = openthread_get_default_instance();
	int ret;

	if (!instance) {
		LOG_ERR("OpenThread not initialized");
		k_mutex_unlock(&nrfcloud_mutex);
		return -ENODEV;
	}

	openthread_mutex_lock();
	otDeviceRole role = otThreadGetDeviceRole(instance);
	openthread_mutex_unlock();

	if (role < OT_DEVICE_ROLE_CHILD) {
		LOG_ERR("Not attached to Thread network (role: %d)", role);
		k_mutex_unlock(&nrfcloud_mutex);
		return -ENETDOWN;
	}

	/* Resolve server */
	otIp6Address server_addr;

	if (!resolve_server(instance, &server_addr)) {
		LOG_ERR("Could not resolve %s", COAP_SERVER_HOST);
		k_mutex_unlock(&nrfcloud_mutex);
		return -EHOSTUNREACH;
	}

	char addr_str[OT_IP6_ADDRESS_STRING_SIZE];

	otIp6AddressToString(&server_addr, addr_str, sizeof(addr_str));
	LOG_INF("Connecting to [%s]:%d ...", addr_str, COAP_SERVER_PORT);

	/* Open OT UDP socket */
	s->bio.instance = instance;
	s->bio.peer_addr = server_addr;
	s->bio.peer_port = COAP_SERVER_PORT;

	k_msgq_purge(&rx_msgq);

	openthread_mutex_lock();
	memset(&s->bio.socket, 0, sizeof(s->bio.socket));

	otError ot_err = otUdpOpen(instance, &s->bio.socket, ot_udp_recv_cb, NULL);

	if (ot_err != OT_ERROR_NONE) {
		openthread_mutex_unlock();
		LOG_ERR("otUdpOpen failed: %d", ot_err);
		k_mutex_unlock(&nrfcloud_mutex);
		return -EIO;
	}

	otSockAddr bind_addr;

	memset(&bind_addr, 0, sizeof(bind_addr));
	otUdpBind(instance, &s->bio.socket, &bind_addr, OT_NETIF_THREAD);
	openthread_mutex_unlock();

	/* Init mbedTLS contexts */
	mbedtls_ssl_init(&s->ssl);
	mbedtls_ssl_config_init(&s->conf);
	mbedtls_x509_crt_init(&s->ca_cert);

	/* Parse CA certificate for server verification */
	ret = mbedtls_x509_crt_parse(&s->ca_cert,
				     (const unsigned char *)nrfcloud_ca_cert,
				     sizeof(nrfcloud_ca_cert));
	if (ret != 0) {
		LOG_ERR("CA cert parse failed: -0x%04x", -ret);
		goto cleanup;
	}

	/* Configure DTLS client */
	ret = mbedtls_ssl_config_defaults(&s->conf,
					  MBEDTLS_SSL_IS_CLIENT,
					  MBEDTLS_SSL_TRANSPORT_DATAGRAM,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		LOG_ERR("ssl_config_defaults failed: -0x%04x", -ret);
		goto cleanup;
	}

	mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&s->conf, &s->ca_cert, NULL);
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
	/*
	 * NCS 3.4.0 ships an mbedTLS where mbedtls_ssl_conf_rng() no longer
	 * exists when MBEDTLS_USE_PSA_CRYPTO is enabled — the SSL layer draws
	 * randomness from PSA itself, so configuring an RNG callback is both
	 * unnecessary and unavailable. Kept for 3.2.x/3.3.x, where it is still
	 * required.
	 */
	mbedtls_ssl_conf_rng(&s->conf, dtls_rng, NULL);
#endif

	ret = mbedtls_ssl_setup(&s->ssl, &s->conf);
	if (ret != 0) {
		LOG_ERR("ssl_setup failed: -0x%04x", -ret);
		goto cleanup;
	}

	mbedtls_ssl_set_hostname(&s->ssl, COAP_SERVER_HOST);
	mbedtls_ssl_set_cid(&s->ssl, MBEDTLS_SSL_CID_ENABLED, NULL, 0);
	mbedtls_ssl_set_bio(&s->ssl, s, bio_send, NULL, bio_recv_timeout);
	mbedtls_ssl_set_timer_cb(&s->ssl, s, dtls_timer_set, dtls_timer_get);

	/* DTLS handshake */
	LOG_INF("DTLS handshake...");

	do {
		ret = mbedtls_ssl_handshake(&s->ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		 ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (ret != 0) {
		LOG_ERR("DTLS handshake FAILED: -0x%04x", -ret);
		goto cleanup;
	}

	LOG_INF("DTLS OK (%s)", mbedtls_ssl_get_ciphersuite(&s->ssl));

	/* Generate JWT */
	uint32_t now = get_current_time();

	if (now == 0) {
		LOG_ERR("Time not set");
		ret = -EINVAL;
		goto disconnect;
	}

	static char jwt_buf[512];
	psa_key_id_t jwt_key;

	ret = jwt_signing_key(&jwt_key);
	if (ret != 0) {
		LOG_ERR("No signing key available: %d", ret);
		goto disconnect;
	}

	ret = jwt_generate_psa(DEVICE_ID, now, jwt_key, jwt_buf, sizeof(jwt_buf));
	if (ret != 0) {
		LOG_ERR("JWT generation failed: %d", ret);
		goto disconnect;
	}

	LOG_INF("JWT generated (%d bytes)", (int)strlen(jwt_buf));

	/* CoAP POST /auth/jwt */
	static uint8_t coap_buf[600];
	uint8_t token = coap_random_token();
	int pkt_len;

	pkt_len = coap_build_post(coap_buf, sizeof(coap_buf),
				  "auth", "jwt",
				  (const uint8_t *)jwt_buf, strlen(jwt_buf),
				  token);
	if (pkt_len < 0) {
		LOG_ERR("CoAP packet build failed");
		ret = pkt_len;
		goto disconnect;
	}

	LOG_INF("Sending POST /auth/jwt ...");

	ret = mbedtls_ssl_write(&s->ssl, coap_buf, pkt_len);
	if (ret < 0) {
		LOG_ERR("ssl_write failed: -0x%04x", -ret);
		goto disconnect;
	}

	/* Read CoAP response */
	ret = mbedtls_ssl_read(&s->ssl, coap_buf, sizeof(coap_buf));
	if (ret < 0) {
		LOG_ERR("ssl_read failed: -0x%04x", -ret);
		goto disconnect;
	}

	int coap_code = coap_parse_response(coap_buf, ret);

	LOG_INF("Auth response: %d.%02d", coap_code / 100, coap_code % 100);

	if (coap_code != 201) {
		LOG_ERR("Authentication failed");
		ret = -EACCES;
		goto disconnect;
	}

	LOG_INF("Authenticated to nRF Cloud");
	return 0;

disconnect:
	mbedtls_ssl_close_notify(&s->ssl);
cleanup:
	mbedtls_ssl_free(&s->ssl);
	mbedtls_ssl_config_free(&s->conf);
	mbedtls_x509_crt_free(&s->ca_cert);
	openthread_mutex_lock();
	otUdpClose(instance, &s->bio.socket);
	openthread_mutex_unlock();
	k_mutex_unlock(&nrfcloud_mutex);
	return ret;
}

void nrfcloud_disconnect(struct nrfcloud_session *s)
{
	mbedtls_ssl_close_notify(&s->ssl);
	mbedtls_ssl_free(&s->ssl);
	mbedtls_ssl_config_free(&s->conf);
	mbedtls_x509_crt_free(&s->ca_cert);
	openthread_mutex_lock();
	otUdpClose(s->bio.instance, &s->bio.socket);
	openthread_mutex_unlock();
	k_mutex_unlock(&nrfcloud_mutex);
}

int nrfcloud_send(struct nrfcloud_session *s, const uint8_t *buf, size_t len)
{
	return mbedtls_ssl_write(&s->ssl, buf, len);
}

int nrfcloud_recv(struct nrfcloud_session *s, uint8_t *buf, size_t buf_size)
{
	return mbedtls_ssl_read(&s->ssl, buf, buf_size);
}
