#include "jwt.h"
#include "credentials.h"

#ifdef CONFIG_PROVISIONING
#include "provisioning.h"
#endif

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/base64.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>
#include <psa/crypto.h>
#include <string.h>
#include <stdio.h>

#include <openthread.h>
#include <openthread/udp.h>
#include <openthread/dns_client.h>
#include <openthread/nat64.h>

LOG_MODULE_REGISTER(jwt, LOG_LEVEL_INF);

/* Wall-clock time set via shell command */
static uint32_t wall_clock_time;
static int64_t wall_clock_uptime_ref;

static void base64url_fixup(char *b64, size_t *len)
{
	size_t out = 0;

	for (size_t i = 0; i < *len; i++) {
		if (b64[i] == '+') {
			b64[out++] = '-';
		} else if (b64[i] == '/') {
			b64[out++] = '_';
		} else if (b64[i] == '=') {
			/* strip padding */
		} else {
			b64[out++] = b64[i];
		}
	}
	b64[out] = '\0';
	*len = out;
}

static int base64url_encode(const uint8_t *data, size_t data_len,
			    char *out, size_t out_size, size_t *out_len)
{
	int ret;
	size_t olen;

	ret = base64_encode(out, out_size, &olen, data, data_len);
	if (ret != 0) {
		return ret;
	}

	base64url_fixup(out, &olen);
	*out_len = olen;
	return 0;
}

int jwt_generate_psa(const char *device_id, uint32_t unix_time,
		     psa_key_id_t key_id,
		     char *jwt_buf, size_t jwt_buf_size)
{
	static const char header_json[] = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
	char payload_json[128];
	char b64_buf[256];
	size_t b64_len;
	size_t offset = 0;
	int ret;
	psa_status_t status;

	/* Encode header */
	ret = base64url_encode((const uint8_t *)header_json, strlen(header_json),
			       b64_buf, sizeof(b64_buf), &b64_len);
	if (ret != 0) {
		return -ENOMEM;
	}
	if (offset + b64_len + 1 >= jwt_buf_size) {
		return -ENOMEM;
	}
	memcpy(jwt_buf + offset, b64_buf, b64_len);
	offset += b64_len;
	jwt_buf[offset++] = '.';

	/* Build and encode payload */
	ret = snprintf(payload_json, sizeof(payload_json),
		       "{\"sub\":\"%s\",\"iat\":%u,\"exp\":%u}",
		       device_id, unix_time, unix_time + 3600);
	if (ret < 0 || ret >= (int)sizeof(payload_json)) {
		return -ENOMEM;
	}

	ret = base64url_encode((const uint8_t *)payload_json, strlen(payload_json),
			       b64_buf, sizeof(b64_buf), &b64_len);
	if (ret != 0) {
		return -ENOMEM;
	}
	if (offset + b64_len >= jwt_buf_size) {
		return -ENOMEM;
	}
	memcpy(jwt_buf + offset, b64_buf, b64_len);
	offset += b64_len;
	jwt_buf[offset] = '\0';

	/* Sign header.payload with the caller's key */
	uint8_t signature[64];
	size_t sig_len;

	status = psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				  (const uint8_t *)jwt_buf, offset,
				  signature, sizeof(signature), &sig_len);

	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_sign_message failed: %d", status);
		return -EIO;
	}

	/* Append dot + base64url signature */
	jwt_buf[offset++] = '.';

	ret = base64url_encode(signature, sig_len,
			       b64_buf, sizeof(b64_buf), &b64_len);
	if (ret != 0) {
		return -ENOMEM;
	}
	if (offset + b64_len >= jwt_buf_size) {
		return -ENOMEM;
	}
	memcpy(jwt_buf + offset, b64_buf, b64_len);
	offset += b64_len;
	jwt_buf[offset] = '\0';

	return 0;
}

int jwt_generate(const char *device_id, uint32_t unix_time,
		 const uint8_t *priv_key, size_t key_len,
		 char *jwt_buf, size_t jwt_buf_size)
{
	psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	psa_status_t status;
	int ret;

	if (key_len != 32) {
		return -EINVAL;
	}

	psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attr, 256);
	psa_set_key_lifetime(&key_attr, PSA_KEY_LIFETIME_VOLATILE);

	status = psa_import_key(&key_attr, priv_key, key_len, &key_id);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_import_key failed: %d", status);
		return -EIO;
	}

	ret = jwt_generate_psa(device_id, unix_time, key_id,
			       jwt_buf, jwt_buf_size);

	psa_destroy_key(key_id);
	return ret;
}

/*
 * Resolve the signing key: the provisioned on-die key when the device has one,
 * otherwise the compiled-in demo key. Keeps callers from having to know which
 * identity model a given unit was built with.
 */
int jwt_signing_key(psa_key_id_t *key_id)
{
#ifdef CONFIG_PROVISIONING
	return provisioning_get_signing_key(key_id);
#else
	psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
	static psa_key_id_t cached = PSA_KEY_ID_NULL;
	psa_status_t status;

	if (cached != PSA_KEY_ID_NULL) {
		*key_id = cached;
		return 0;
	}

	psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attr, 256);
	psa_set_key_lifetime(&key_attr, PSA_KEY_LIFETIME_VOLATILE);

	status = psa_import_key(&key_attr, private_key, sizeof(private_key), &cached);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_import_key failed: %d", status);
		return -EIO;
	}

	*key_id = cached;
	return 0;
#endif
}

uint32_t get_current_time(void)
{
	if (wall_clock_time == 0) {
		return 0;
	}
	int64_t elapsed = (k_uptime_get() - wall_clock_uptime_ref) / 1000;
	return wall_clock_time + (uint32_t)elapsed;
}

#ifdef CONFIG_SHELL
int cmd_nrfcloud_jwt(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t now = get_current_time();

	if (now == 0) {
		shell_error(sh, "Time not set. Use: nrfcloud time <unix_timestamp>");
		return -EINVAL;
	}

	static char jwt_buf[512];
	psa_key_id_t key_id;
	int ret;

	ret = jwt_signing_key(&key_id);
	if (ret != 0) {
		shell_error(sh, "No signing key: %d (run 'provision keygen')", ret);
		return ret;
	}

	ret = jwt_generate_psa(DEVICE_ID, now, key_id, jwt_buf, sizeof(jwt_buf));
	if (ret != 0) {
		shell_error(sh, "JWT generation failed: %d", ret);
		return ret;
	}

	shell_print(sh, "%s", jwt_buf);
	return 0;
}
#endif /* CONFIG_SHELL */

#ifdef CONFIG_SHELL
int cmd_nrfcloud_time(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		if (wall_clock_time == 0) {
			shell_print(sh, "Time not set");
		} else {
			shell_print(sh, "Current time: %u", get_current_time());
		}
		return 0;
	}

	wall_clock_time = (uint32_t)strtoul(argv[1], NULL, 10);
	wall_clock_uptime_ref = k_uptime_get();

	shell_print(sh, "Time set to %u", wall_clock_time);
	return 0;
}
#endif /* CONFIG_SHELL */

/* --- SNTP over NAT64 --- */

#define SNTP_PORT 123
#define SNTP_PACKET_SIZE 48
#define SNTP_TIMEOUT_MS  5000

/* NTP epoch (1900-01-01) to Unix epoch (1970-01-01) offset */
#define NTP_UNIX_OFFSET 2208988800UL

/* Fallback IPv4 for time.google.com — used when DNS64 is unavailable */
#define SNTP_FALLBACK_IPV4 "216.239.35.0"

static K_SEM_DEFINE(sntp_sem, 0, 1);
static uint32_t sntp_rx_time;
static bool sntp_rx_ok;

static void sntp_recv_cb(void *aContext, otMessage *aMessage,
			 const otMessageInfo *aMessageInfo)
{
	uint8_t buf[SNTP_PACKET_SIZE];
	uint16_t offset = otMessageGetOffset(aMessage);
	uint16_t length = otMessageGetLength(aMessage) - offset;

	if (length < SNTP_PACKET_SIZE) {
		sntp_rx_ok = false;
		k_sem_give(&sntp_sem);
		return;
	}

	otMessageRead(aMessage, offset, buf, SNTP_PACKET_SIZE);

	/* Transmit timestamp is at bytes 40-43 (big-endian NTP seconds) */
	uint32_t ntp_secs = sys_get_be32(&buf[40]);
	sntp_rx_time = ntp_secs - NTP_UNIX_OFFSET;
	sntp_rx_ok = true;
	k_sem_give(&sntp_sem);
}

static void sntp_dns_cb(otError aError, const otDnsAddressResponse *aResponse,
			void *aContext)
{
	otIp6Address *addr = aContext;

	if (aError != OT_ERROR_NONE) {
		sntp_rx_ok = false;
		k_sem_give(&sntp_sem);
		return;
	}

	uint32_t ttl;

	if (otDnsAddressResponseGetAddress(aResponse, 0, addr, &ttl) != OT_ERROR_NONE) {
		sntp_rx_ok = false;
		k_sem_give(&sntp_sem);
		return;
	}

	sntp_rx_ok = true;
	k_sem_give(&sntp_sem);
}

int sntp_sync(const char *hostname)
{
	const char *host = hostname ? hostname : "time.google.com";
	otInstance *instance = openthread_get_default_instance();

	if (!instance) {
		LOG_ERR("OpenThread not initialized");
		return -ENODEV;
	}

	LOG_INF("SNTP: resolving %s ...", host);
	otIp6Address dest;
	otIp4Address ipv4;
	bool have_ipv4 = (otIp4AddressFromString(host, &ipv4) == OT_ERROR_NONE);

	if (!have_ipv4) {
		/* Try DNS64 (A record → synthesized IPv6) */
		k_sem_reset(&sntp_sem);
		sntp_rx_ok = false;

		openthread_mutex_lock();
		otError dns_err = otDnsClientResolveIp4Address(instance, host,
							       sntp_dns_cb, &dest, NULL);
		openthread_mutex_unlock();

		if (dns_err == OT_ERROR_NONE) {
			k_sem_take(&sntp_sem, K_SECONDS(10));
		}

		if (dns_err != OT_ERROR_NONE || !sntp_rx_ok) {
			LOG_WRN("SNTP: DNS failed, synthesizing NAT64 from %s", SNTP_FALLBACK_IPV4);
			otIp4AddressFromString(SNTP_FALLBACK_IPV4, &ipv4);
			have_ipv4 = true;
		}
	}

	if (have_ipv4) {
		openthread_mutex_lock();
		otError err = otNat64SynthesizeIp6Address(instance, &ipv4, &dest);
		openthread_mutex_unlock();

		if (err != OT_ERROR_NONE) {
			LOG_ERR("SNTP: NAT64 synthesis failed: %d", err);
			return -EIO;
		}
	}

	/* Build SNTP request: version 4, client mode */
	uint8_t sntp_req[SNTP_PACKET_SIZE];
	memset(sntp_req, 0, sizeof(sntp_req));
	sntp_req[0] = 0x23; /* LI=0, VN=4, Mode=3 (client) */

	/* Send via OT UDP */
	otUdpSocket socket;
	otSockAddr bind_addr;
	otMessageInfo msg_info;
	otError err;

	k_sem_reset(&sntp_sem);
	sntp_rx_ok = false;

	openthread_mutex_lock();

	memset(&socket, 0, sizeof(socket));
	err = otUdpOpen(instance, &socket, sntp_recv_cb, NULL);
	if (err != OT_ERROR_NONE) {
		openthread_mutex_unlock();
		LOG_ERR("SNTP: otUdpOpen failed: %d", err);
		return -EIO;
	}

	memset(&bind_addr, 0, sizeof(bind_addr));
	err = otUdpBind(instance, &socket, &bind_addr, OT_NETIF_THREAD);
	if (err != OT_ERROR_NONE) {
		otUdpClose(instance, &socket);
		openthread_mutex_unlock();
		LOG_ERR("SNTP: otUdpBind failed: %d", err);
		return -EIO;
	}

	otMessage *ot_msg = otUdpNewMessage(instance, NULL);
	if (!ot_msg) {
		otUdpClose(instance, &socket);
		openthread_mutex_unlock();
		LOG_ERR("SNTP: otUdpNewMessage failed");
		return -ENOMEM;
	}

	err = otMessageAppend(ot_msg, sntp_req, sizeof(sntp_req));
	if (err != OT_ERROR_NONE) {
		otMessageFree(ot_msg);
		otUdpClose(instance, &socket);
		openthread_mutex_unlock();
		LOG_ERR("SNTP: otMessageAppend failed: %d", err);
		return -EIO;
	}

	memset(&msg_info, 0, sizeof(msg_info));
	msg_info.mPeerAddr = dest;
	msg_info.mPeerPort = SNTP_PORT;

	err = otUdpSend(instance, &socket, ot_msg, &msg_info);
	if (err != OT_ERROR_NONE) {
		otUdpClose(instance, &socket);
		openthread_mutex_unlock();
		LOG_ERR("SNTP: otUdpSend failed: %d", err);
		return -EIO;
	}

	openthread_mutex_unlock();

	/* Wait for response */
	if (k_sem_take(&sntp_sem, K_MSEC(SNTP_TIMEOUT_MS)) != 0 || !sntp_rx_ok) {
		openthread_mutex_lock();
		otUdpClose(instance, &socket);
		openthread_mutex_unlock();
		LOG_ERR("SNTP: timeout");
		return -ETIMEDOUT;
	}

	openthread_mutex_lock();
	otUdpClose(instance, &socket);
	openthread_mutex_unlock();

	/* Set wall clock */
	wall_clock_time = sntp_rx_time;
	wall_clock_uptime_ref = k_uptime_get();

	LOG_INF("SNTP: time set to %u", wall_clock_time);
	return 0;
}

#ifdef CONFIG_SHELL
int cmd_nrfcloud_sntp(const struct shell *sh, size_t argc, char **argv)
{
	const char *host = (argc >= 2) ? argv[1] : NULL;
	int ret = sntp_sync(host);

	if (ret == 0) {
		shell_print(sh, "Time set to %u (via SNTP)", get_current_time());
	} else {
		shell_error(sh, "SNTP sync failed: %d", ret);
	}
	return ret;
}
#endif /* CONFIG_SHELL */

