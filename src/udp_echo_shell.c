#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>

#include <openthread.h>
#include <openthread/udp.h>
#include <openthread/dns_client.h>
#include <openthread/nat64.h>
#include <openthread/ip6.h>
#include <openthread/thread.h>
#include <openthread/message.h>

#include <string.h>

LOG_MODULE_REGISTER(udp_echo, LOG_LEVEL_INF);

#define ECHO_SERVER_HOST "udp-echo.nordicsemi.academy"
#define ECHO_SERVER_PORT 2444
#define RECV_TIMEOUT_MS  5000
#define RECV_BUF_SIZE    256

/* Pre-resolved addresses for the echo server. The HomePod's Thread DNS proxy
 * cannot follow the CNAME chain (udp-echo.nordicsemi.academy -> containerhost01
 * .endpoints.nordicsemi.academy), so DNS resolution fails. We fall back to these.
 */
#define ECHO_SERVER_IPV6 "2603:1020:203:3::c6"
#define ECHO_SERVER_IPV4 "20.82.16.164"

/* Synchronization for async DNS */
static K_SEM_DEFINE(dns_sem, 0, 1);
static otIp6Address resolved_addr;
static bool dns_resolved_ok;

/* Synchronization for async UDP receive */
static K_SEM_DEFINE(udp_recv_sem, 0, 1);
static char udp_recv_buf[RECV_BUF_SIZE];
static int udp_recv_len;

static void udp_receive_cb(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
	uint16_t offset = otMessageGetOffset(aMessage);
	uint16_t length = otMessageGetLength(aMessage) - offset;

	if (length > sizeof(udp_recv_buf) - 1) {
		length = sizeof(udp_recv_buf) - 1;
	}

	udp_recv_len = otMessageRead(aMessage, offset, udp_recv_buf, length);
	udp_recv_buf[udp_recv_len] = '\0';

	k_sem_give(&udp_recv_sem);
}

static void send_udp_and_print(const struct shell *sh, otInstance *instance,
			       const otIp6Address *addr, const char *msg)
{
	otUdpSocket socket;
	otSockAddr bind_addr;
	otMessageInfo msg_info;
	otMessage *ot_msg;
	otError err;
	char addr_str[OT_IP6_ADDRESS_STRING_SIZE];

	otIp6AddressToString(addr, addr_str, sizeof(addr_str));
	shell_print(sh, "Sending to [%s]:%d", addr_str, ECHO_SERVER_PORT);

	openthread_mutex_lock();

	memset(&socket, 0, sizeof(socket));
	err = otUdpOpen(instance, &socket, udp_receive_cb, NULL);
	if (err != OT_ERROR_NONE) {
		openthread_mutex_unlock();
		shell_error(sh, "otUdpOpen failed: %d", err);
		return;
	}

	memset(&bind_addr, 0, sizeof(bind_addr));
	err = otUdpBind(instance, &socket, &bind_addr, OT_NETIF_THREAD);
	if (err != OT_ERROR_NONE) {
		otUdpClose(instance, &socket);
		openthread_mutex_unlock();
		shell_error(sh, "otUdpBind failed: %d", err);
		return;
	}

	ot_msg = otUdpNewMessage(instance, NULL);
	if (!ot_msg) {
		otUdpClose(instance, &socket);
		openthread_mutex_unlock();
		shell_error(sh, "otUdpNewMessage failed (no buffers)");
		return;
	}

	err = otMessageAppend(ot_msg, msg, (uint16_t)strlen(msg));
	if (err != OT_ERROR_NONE) {
		otMessageFree(ot_msg);
		otUdpClose(instance, &socket);
		openthread_mutex_unlock();
		shell_error(sh, "otMessageAppend failed: %d", err);
		return;
	}

	memset(&msg_info, 0, sizeof(msg_info));
	msg_info.mPeerAddr = *addr;
	msg_info.mPeerPort = ECHO_SERVER_PORT;

	k_sem_reset(&udp_recv_sem);
	udp_recv_len = 0;

	err = otUdpSend(instance, &socket, ot_msg, &msg_info);
	if (err != OT_ERROR_NONE) {
		otUdpClose(instance, &socket);
		openthread_mutex_unlock();
		shell_error(sh, "otUdpSend failed: %d", err);
		return;
	}

	openthread_mutex_unlock();
	shell_print(sh, "Sent %d bytes: \"%s\"", (int)strlen(msg), msg);

	if (k_sem_take(&udp_recv_sem, K_MSEC(RECV_TIMEOUT_MS)) == 0) {
		shell_print(sh, "Received %d bytes: \"%s\"", udp_recv_len, udp_recv_buf);
	} else {
		shell_warn(sh, "No response (timeout %d ms)", RECV_TIMEOUT_MS);
	}

	openthread_mutex_lock();
	otUdpClose(instance, &socket);
	openthread_mutex_unlock();
}

/* DNS resolution callback */
static void dns_resolve_cb(otError aError, const otDnsAddressResponse *aResponse, void *aContext)
{
	if (aError != OT_ERROR_NONE) {
		LOG_ERR("DNS resolution failed: %d", aError);
		dns_resolved_ok = false;
		k_sem_give(&dns_sem);
		return;
	}

	uint32_t ttl;
	otError err = otDnsAddressResponseGetAddress(aResponse, 0, &resolved_addr, &ttl);

	if (err != OT_ERROR_NONE) {
		LOG_WRN("DNS response had no address records (error %d)", err);
		dns_resolved_ok = false;
	} else {
		dns_resolved_ok = true;
	}

	k_sem_give(&dns_sem);
}

/* Try DNS resolution, return true on success (result in resolved_addr) */
static bool try_dns_resolve(const struct shell *sh, otInstance *instance, bool nat64)
{
	k_sem_reset(&dns_sem);
	dns_resolved_ok = false;

	openthread_mutex_lock();
	otError err;

	if (nat64) {
		err = otDnsClientResolveIp4Address(instance, ECHO_SERVER_HOST,
						   dns_resolve_cb, NULL, NULL);
	} else {
		err = otDnsClientResolveAddress(instance, ECHO_SERVER_HOST,
						dns_resolve_cb, NULL, NULL);
	}
	openthread_mutex_unlock();

	if (err != OT_ERROR_NONE) {
		return false;
	}

	if (k_sem_take(&dns_sem, K_SECONDS(10)) != 0) {
		return false;
	}

	return dns_resolved_ok;
}

static int cmd_echo_ipv6(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_error(sh, "Usage: echo ipv6 <message>");
		return -EINVAL;
	}

	const char *msg = argv[1];
	otInstance *instance = openthread_get_default_instance();

	if (!instance) {
		shell_error(sh, "OpenThread not initialized");
		return -ENODEV;
	}

	otIp6Address dest;

	/* Try DNS first */
	shell_print(sh, "Resolving %s (AAAA)...", ECHO_SERVER_HOST);
	if (try_dns_resolve(sh, instance, false)) {
		dest = resolved_addr;
	} else {
		shell_warn(sh, "DNS failed, using hardcoded address %s", ECHO_SERVER_IPV6);
		if (otIp6AddressFromString(ECHO_SERVER_IPV6, &dest) != OT_ERROR_NONE) {
			shell_error(sh, "Invalid hardcoded IPv6 address");
			return -EINVAL;
		}
	}

	send_udp_and_print(sh, instance, &dest, msg);
	return 0;
}

static int cmd_echo_nat64(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_error(sh, "Usage: echo nat64 <message>");
		return -EINVAL;
	}

	const char *msg = argv[1];
	otInstance *instance = openthread_get_default_instance();

	if (!instance) {
		shell_error(sh, "OpenThread not initialized");
		return -ENODEV;
	}

	otIp6Address dest;

	/* Try DNS first (OT DNS client auto-synthesizes NAT64 for A records) */
	shell_print(sh, "Resolving %s (A via NAT64)...", ECHO_SERVER_HOST);
	if (try_dns_resolve(sh, instance, true)) {
		dest = resolved_addr;
	} else {
		/* Fall back: manually synthesize NAT64 address from IPv4 */
		shell_warn(sh, "DNS failed, synthesizing NAT64 from %s", ECHO_SERVER_IPV4);

		otIp4Address ipv4;

		if (otIp4AddressFromString(ECHO_SERVER_IPV4, &ipv4) != OT_ERROR_NONE) {
			shell_error(sh, "Invalid IPv4 address");
			return -EINVAL;
		}

		openthread_mutex_lock();
		otError err = otNat64SynthesizeIp6Address(instance, &ipv4, &dest);
		openthread_mutex_unlock();

		if (err != OT_ERROR_NONE) {
			shell_error(sh, "NAT64 synthesis failed: %d (no prefix from border router?)", err);
			return -EIO;
		}
	}

	send_udp_and_print(sh, instance, &dest, msg);
	return 0;
}

static int cmd_echo_send(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 3) {
		shell_error(sh, "Usage: echo send <ipv6-addr> <message>");
		return -EINVAL;
	}

	otInstance *instance = openthread_get_default_instance();

	if (!instance) {
		shell_error(sh, "OpenThread not initialized");
		return -ENODEV;
	}

	otIp6Address dest;

	if (otIp6AddressFromString(argv[1], &dest) != OT_ERROR_NONE) {
		shell_error(sh, "Invalid IPv6 address: %s", argv[1]);
		return -EINVAL;
	}

	send_udp_and_print(sh, instance, &dest, argv[2]);
	return 0;
}

static int cmd_echo_status(const struct shell *sh, size_t argc, char **argv)
{
	otInstance *instance = openthread_get_default_instance();

	if (!instance) {
		shell_error(sh, "OpenThread not initialized");
		return -ENODEV;
	}

	openthread_mutex_lock();

	otDeviceRole role = otThreadGetDeviceRole(instance);
	const char *role_str;

	switch (role) {
	case OT_DEVICE_ROLE_DISABLED:
		role_str = "disabled";
		break;
	case OT_DEVICE_ROLE_DETACHED:
		role_str = "detached";
		break;
	case OT_DEVICE_ROLE_CHILD:
		role_str = "child";
		break;
	case OT_DEVICE_ROLE_ROUTER:
		role_str = "router";
		break;
	case OT_DEVICE_ROLE_LEADER:
		role_str = "leader";
		break;
	default:
		role_str = "unknown";
		break;
	}

	shell_print(sh, "Thread role: %s", role_str);

	const otNetifAddress *addr = otIp6GetUnicastAddresses(instance);

	while (addr) {
		char buf[OT_IP6_ADDRESS_STRING_SIZE];

		otIp6AddressToString(&addr->mAddress, buf, sizeof(buf));
		shell_print(sh, "  IPv6: %s", buf);
		addr = addr->mNext;
	}

	openthread_mutex_unlock();

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(echo_sub,
	SHELL_CMD_ARG(ipv6, NULL,
		"Send UDP echo over IPv6 (direct AAAA)\n"
		"Usage: echo ipv6 <message>",
		cmd_echo_ipv6, 2, 0),
	SHELL_CMD_ARG(nat64, NULL,
		"Send UDP echo over IPv4 via NAT64\n"
		"Usage: echo nat64 <message>",
		cmd_echo_nat64, 2, 0),
	SHELL_CMD_ARG(send, NULL,
		"Send UDP echo to explicit IPv6 address\n"
		"Usage: echo send <ipv6-addr> <message>",
		cmd_echo_send, 3, 0),
	SHELL_CMD(status, NULL,
		"Show Thread network status and addresses",
		cmd_echo_status),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(echo, &echo_sub, "UDP echo commands", NULL);
