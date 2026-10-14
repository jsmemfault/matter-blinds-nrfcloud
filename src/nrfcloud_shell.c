/*
 * nRF Cloud shell commands.
 *
 * Orchestrates DTLS transport, CoAP codec, JWT, and Memfault
 * into user-facing shell commands under "nrfcloud".
 */

#include "dtls_transport.h"
#include "coap_codec.h"
#include "credentials.h"
#include "jwt.h"

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/storage/stream_flash.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/sys/reboot.h>

#include <string.h>

#ifdef CONFIG_MEMFAULT
#include <memfault/core/data_packetizer.h>
#include <memfault/core/platform/device_info.h>
#endif

/*
 * MCUboot secondary slot identifier.
 *
 * With Partition Manager (NCS 3.2.x/3.3.x) the slot is the PM partition
 * 'mcuboot_secondary'. NCS 3.4.0 declares Matter partitions in devicetree with
 * PM disabled, where the same region is the 'slot1_partition' node in external
 * flash. Same address and size either way — only the name differs.
 */
#ifdef CONFIG_PARTITION_MANAGER_ENABLED
#define OTA_SECONDARY_PARTITION_ID FIXED_PARTITION_ID(mcuboot_secondary)
#else
#define OTA_SECONDARY_PARTITION_ID FIXED_PARTITION_ID(slot1_partition)
#endif

LOG_MODULE_REGISTER(nrfcloud_shell, LOG_LEVEL_INF);

/* Memfault chunk proxy URL prefix */
#define MEMFAULT_CHUNKS_URL \
	"https://chunks.memfault.com/api/v0/chunks/" DEVICE_ID

/* Memfault OTA release check */
#define MEMFAULT_RELEASE_API_HOST "device.memfault.com"
#define MEMFAULT_HW_VERSION       CONFIG_MEMFAULT_NCS_HW_VERSION
#define MEMFAULT_SW_TYPE          CONFIG_MEMFAULT_NCS_FW_TYPE

/*
 * The firmware version is generated, so it exists only at runtime.
 *
 * With MEMFAULT_NCS_FW_VERSION_AUTO the version is "<VERSION file>+<build id>",
 * assembled on first call in the NCS port. The OTA release check must report
 * exactly what the device reports to Memfault, or the server compares the
 * wrong versions and either withholds an update or offers one already
 * installed -- so read it from the same place rather than rebuilding it here.
 */
static const char *memfault_fw_version(void)
{
	sMemfaultDeviceInfo info;

	memfault_platform_get_device_info(&info);
	return info.software_version;
}

/* --- nrfcloud connect --- */

static int cmd_nrfcloud_connect(const struct shell *sh, size_t argc,
				char **argv)
{
	struct nrfcloud_session s;
	int ret;

	ret = nrfcloud_connect(&s);
	if (ret != 0) {
		return ret;
	}

	/* Send test message to /msg/d2c */
	uint32_t now = get_current_time();

	static uint8_t coap_buf[600];
	char msg_payload[128];
	uint8_t token = coap_random_token();
	int pkt_len;

	snprintf(msg_payload, sizeof(msg_payload),
		 "{\"appId\":\"TEMP\",\"messageType\":\"DATA\","
		 "\"data\":\"22.5\",\"ts\":%llu}",
		 (unsigned long long)now * 1000ULL);

	pkt_len = coap_build_post(coap_buf, sizeof(coap_buf),
				  "msg", "d2c",
				  (const uint8_t *)msg_payload,
				  strlen(msg_payload), token);
	if (pkt_len > 0) {
		shell_print(sh, "Sending POST /msg/d2c ...");
		ret = nrfcloud_send(&s, coap_buf, pkt_len);
		if (ret > 0) {
			ret = nrfcloud_recv(&s, coap_buf, sizeof(coap_buf));
			if (ret > 0) {
				int code = coap_parse_response(coap_buf, ret);

				shell_print(sh, "Message response: %d.%02d",
					    code / 100, code % 100);
			}
		}
	}

	nrfcloud_disconnect(&s);
	return 0;
}

/* --- nrfcloud send_memfault --- */

#ifdef CONFIG_MEMFAULT

/*
 * Build a CoAP CON POST to /proxy with Proxy-Uri and Memfault project key.
 * Chunk payload is appended by the caller after the payload marker.
 * Returns position after payload marker, or negative on error.
 */
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

static int cmd_nrfcloud_send_memfault(const struct shell *sh, size_t argc,
				      char **argv)
{
	struct nrfcloud_session s;
	int ret;

	ret = nrfcloud_connect(&s);
	if (ret != 0) {
		return ret;
	}

	static uint8_t pkt_buf[512];
	int chunks_sent = 0;

	while (true) {
		uint8_t token;
		int hdr_len = coap_build_proxy_header(pkt_buf, sizeof(pkt_buf),
						      &token);
		if (hdr_len < 0) {
			shell_error(sh, "CoAP proxy header build failed");
			break;
		}

		size_t chunk_len = sizeof(pkt_buf) - (size_t)hdr_len;
		bool has_data = memfault_packetizer_get_chunk(
			pkt_buf + hdr_len, &chunk_len);

		if (!has_data) {
			break;
		}

		int pkt_len = hdr_len + (int)chunk_len;

		ret = nrfcloud_send(&s, pkt_buf, pkt_len);
		if (ret < 0) {
			shell_error(sh, "send failed: -0x%04x", -ret);
			memfault_packetizer_abort();
			break;
		}

		ret = nrfcloud_recv(&s, pkt_buf, sizeof(pkt_buf));
		if (ret < 0) {
			shell_error(sh, "recv failed: -0x%04x", -ret);
			memfault_packetizer_abort();
			break;
		}

		int code = coap_parse_response(pkt_buf, ret);

		if (code != 201) {
			shell_error(sh, "Chunk upload failed: %d.%02d",
				    code / 100, code % 100);
			memfault_packetizer_abort();
			break;
		}

		chunks_sent++;
		shell_print(sh, "Chunk %d uploaded (%d bytes)", chunks_sent,
			    (int)chunk_len);
	}

	if (chunks_sent == 0) {
		shell_print(sh, "No Memfault data to send");
	} else {
		shell_print(sh, "Uploaded %d Memfault chunk(s)", chunks_sent);
	}

	nrfcloud_disconnect(&s);
	return 0;
}

/* --- nrfcloud ota_check --- */

/*
 * Check for a firmware update via Memfault's Release Management API.
 *
 * Returns:  1 = update available (URL copied to url_out)
 *           0 = up to date / no update
 *          <0 = error
 */
static int memfault_ota_check(const struct shell *sh,
			      struct nrfcloud_session *s,
			      char *url_out, size_t url_out_size)
{
	static uint8_t coap_buf[600];
	char proxy_uri[256];
	int ret;

	ret = snprintf(proxy_uri, sizeof(proxy_uri),
		       "https://%s/api/v0/releases/latest/url"
		       "?device_serial=%s"
		       "&hardware_version=%s"
		       "&software_type=%s"
		       "&current_version=%s",
		       MEMFAULT_RELEASE_API_HOST,
		       DEVICE_ID,
		       MEMFAULT_HW_VERSION,
		       MEMFAULT_SW_TYPE,
		       memfault_fw_version());
	if (ret < 0 || (size_t)ret >= sizeof(proxy_uri)) {
		shell_error(sh, "OTA URL too long");
		return -ENOMEM;
	}

	/*
	 * Build CoAP GET with 8-byte token (matching NCS SDK behavior).
	 * The nRF Cloud proxy expects TKL=8 and a payload marker.
	 * Format: Ver=1, Type=CON, TKL=8, Code=GET, MsgID, Token[8],
	 *         options..., 0xFF (payload marker, no payload body).
	 */
	uint8_t token[8];

	sys_csrand_get(token, sizeof(token));

	/* Build header manually for 8-byte token (coap_start_request uses TKL=1).
	 * Use coap_start_request just to get the next message ID, then override.
	 */
	int pos = coap_start_request(coap_buf, sizeof(coap_buf),
				     COAP_CODE_GET, 0);
	if (pos < 0) {
		return pos;
	}
	/* Overwrite TKL=1 header with TKL=8 and insert 8-byte token */
	coap_buf[0] = 0x48; /* Ver=1, Type=CON, TKL=8 */
	/* bytes 1-4 already set (code, msg_id) by coap_start_request */
	/* Move write position: header(4) + token(8) = 12 */
	memcpy(coap_buf + 4, token, 8);
	pos = 12;

	uint16_t prev_opt = 0;

	pos = coap_append_option(coap_buf, pos, sizeof(coap_buf), &prev_opt,
				 COAP_OPT_URI_PATH, "proxy", 5);
	if (pos < 0) {
		return pos;
	}

	pos = coap_append_option(coap_buf, pos, sizeof(coap_buf), &prev_opt,
				 COAP_OPT_PROXY_URI, proxy_uri,
				 strlen(proxy_uri));
	if (pos < 0) {
		return pos;
	}

	const char *project_key = CONFIG_MEMFAULT_NCS_PROJECT_KEY;

	pos = coap_append_option(coap_buf, pos, sizeof(coap_buf), &prev_opt,
				 COAP_OPT_MEMFAULT_KEY, project_key,
				 strlen(project_key));
	if (pos < 0) {
		return pos;
	}

	/* Payload marker (required by nRF Cloud proxy, even with no body) */
	coap_buf[pos++] = 0xFF;

	shell_print(sh, "Checking for OTA update...");

	ret = nrfcloud_send(s, coap_buf, pos);
	if (ret < 0) {
		shell_error(sh, "send failed: -0x%04x", -ret);
		return -EIO;
	}

	/* Read responses, discarding any with mismatched token
	 * (e.g. retransmitted auth ACKs).
	 */
	struct coap_response resp;
	int attempts;

	for (attempts = 0; attempts < 5; attempts++) {
		ret = nrfcloud_recv(s, coap_buf, sizeof(coap_buf));
		if (ret < 0) {
			shell_error(sh, "recv failed: -0x%04x", -ret);
			return -EIO;
		}

		/* Check TKL matches our 8-byte token */
		uint8_t tkl = coap_buf[0] & 0x0F;

		if (tkl != 8 || ret < 12 ||
		    memcmp(coap_buf + 4, token, 8) != 0) {
			/* Stale packet, discard */
			continue;
		}

		ret = coap_parse_response_full(coap_buf, ret, &resp);
		if (ret < 0) {
			shell_error(sh, "Failed to parse OTA response");
			return ret;
		}
		break;
	}

	if (attempts == 5) {
		shell_error(sh, "No matching response received");
		return -ETIMEDOUT;
	}

	shell_print(sh, "OTA response: %d.%02d", resp.code / 100,
		    resp.code % 100);

	if (resp.code == 205 && resp.payload_len > 0) {
		size_t copy_len = resp.payload_len;

		if (copy_len >= url_out_size) {
			copy_len = url_out_size - 1;
		}
		memcpy(url_out, resp.payload, copy_len);
		url_out[copy_len] = '\0';
		return 1;
	}

	return 0;
}

static int cmd_nrfcloud_ota_check(const struct shell *sh, size_t argc,
				  char **argv)
{
	struct nrfcloud_session s;
	int ret;

	ret = nrfcloud_connect(&s);
	if (ret != 0) {
		return ret;
	}

	static char url_buf[400];

	ret = memfault_ota_check(sh, &s, url_buf, sizeof(url_buf));

	if (ret > 0) {
		shell_print(sh, "Update available: %s", url_buf);
	} else if (ret == 0) {
		shell_print(sh, "Up to date (current: %s)", memfault_fw_version());
	}

	nrfcloud_disconnect(&s);
	return (ret < 0) ? ret : 0;
}

/* --- nrfcloud ota_download --- */

/*
 * Build a Block2 GET request with 8-byte token for firmware download.
 * No project key — CDN URL doesn't need it.
 */
static int build_block_request(uint8_t *buf, size_t buf_size,
			       const char *download_url,
			       uint32_t block_num, uint8_t szx,
			       const uint8_t *token8)
{
	int pos = coap_start_request(buf, buf_size, COAP_CODE_GET, 0);

	if (pos < 0) {
		return pos;
	}

	buf[0] = 0x48; /* TKL=8 */
	memcpy(buf + 4, token8, 8);
	pos = 12;

	uint16_t prev_opt = 0;

	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_URI_PATH, "proxy", 5);
	if (pos < 0) {
		return pos;
	}

	unsigned int block2_val = (block_num << 4) | (szx & 0x07);
	uint8_t block2_buf[3];
	int block2_len = coap_encode_uint(block2_buf, block2_val);

	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_BLOCK2, block2_buf, block2_len);
	if (pos < 0) {
		return pos;
	}

	pos = coap_append_option(buf, pos, buf_size, &prev_opt,
				 COAP_OPT_PROXY_URI, download_url,
				 strlen(download_url));
	if (pos < 0) {
		return pos;
	}

	buf[pos++] = 0xFF;
	return pos;
}

/*
 * Receive a response matching our 8-byte token, skipping stale packets.
 */
static int recv_block_matching(struct nrfcloud_session *s,
			       uint8_t *buf, size_t buf_size,
			       const uint8_t *token8)
{
	for (int attempt = 0; attempt < 5; attempt++) {
		int ret = nrfcloud_recv(s, buf, buf_size);

		if (ret < 0) {
			return ret;
		}

		uint8_t tkl = buf[0] & 0x0F;

		if (tkl == 8 && ret >= 12 &&
		    memcmp(buf + 4, token8, 8) == 0) {
			return ret;
		}
	}
	return -ETIMEDOUT;
}

static int cmd_nrfcloud_ota(const struct shell *sh, size_t argc,
				     char **argv)
{
	struct nrfcloud_session s;
	int ret;

	/*
	 * Step 1: Connect, check for update, get download URL.
	 */
	ret = nrfcloud_connect(&s);
	if (ret != 0) {
		return ret;
	}

	static char json_buf[400];

	ret = memfault_ota_check(sh, &s, json_buf, sizeof(json_buf));
	if (ret <= 0) {
		if (ret == 0) {
			shell_print(sh, "Up to date (current: %s)",
				    memfault_fw_version());
		}
		nrfcloud_disconnect(&s);
		return (ret < 0) ? ret : 0;
	}

	static char download_url[400];

	ret = coap_extract_json_url(json_buf, strlen(json_buf),
				    download_url, sizeof(download_url));
	if (ret < 0) {
		shell_error(sh, "Failed to extract download URL");
		nrfcloud_disconnect(&s);
		return ret;
	}
	nrfcloud_disconnect(&s);

	/*
	 * Step 2: Erase flash (slow, ~60s). Done offline to avoid
	 * DTLS session timeout.
	 */
	const struct flash_area *fa;

	ret = flash_area_open(OTA_SECONDARY_PARTITION_ID, &fa);
	if (ret != 0) {
		shell_error(sh, "Failed to open secondary partition: %d", ret);
		return ret;
	}

	shell_print(sh, "Erasing secondary slot (%u bytes)...",
		    (unsigned)fa->fa_size);
	ret = flash_area_erase(fa, 0, fa->fa_size);
	if (ret != 0) {
		shell_error(sh, "Flash erase failed: %d", ret);
		flash_area_close(fa);
		return ret;
	}
	shell_print(sh, "Erase complete.");

	/*
	 * Step 3: Reconnect and download firmware via Block2.
	 */
	ret = nrfcloud_connect(&s);
	if (ret != 0) {
		flash_area_close(fa);
		return ret;
	}

	static uint8_t stream_buf[4096] __aligned(4);
	struct stream_flash_ctx stream;

	ret = stream_flash_init(&stream, fa->fa_dev, stream_buf,
				sizeof(stream_buf), fa->fa_off, fa->fa_size,
				NULL);
	if (ret != 0) {
		shell_error(sh, "stream_flash_init failed: %d", ret);
		flash_area_close(fa);
		nrfcloud_disconnect(&s);
		return ret;
	}

	uint8_t dl_token[8];

	sys_csrand_get(dl_token, sizeof(dl_token));

	uint32_t block_num = 0;
	size_t total_bytes = 0;
	static uint8_t coap_buf[1200];

	shell_print(sh, "Downloading firmware...");

	while (true) {
		int pkt_len = build_block_request(coap_buf, sizeof(coap_buf),
						  download_url, block_num,
						  COAP_BLOCK_SZX_1024,
						  dl_token);
		if (pkt_len < 0) {
			ret = pkt_len;
			break;
		}

		/* Retry loop for transient failures */
		struct coap_response blk;
		int retries;

		for (retries = 0; retries < 3; retries++) {
			ret = nrfcloud_send(&s, coap_buf, pkt_len);
			if (ret < 0) {
				continue;
			}

			ret = recv_block_matching(&s, coap_buf,
						  sizeof(coap_buf),
						  dl_token);
			if (ret < 0) {
				shell_print(sh, "  Retry block %u (%d/3)",
					    block_num, retries + 1);
				continue;
			}

			ret = coap_parse_response_full(coap_buf, ret, &blk);
			if (ret == 0 && blk.code == 205) {
				break;
			}
		}

		if (retries == 3) {
			shell_error(sh, "Block %u failed after 3 retries",
				    block_num);
			ret = -EIO;
			break;
		}

		if (blk.payload_len > 0) {
			ret = stream_flash_buffered_write(&stream,
							  blk.payload,
							  blk.payload_len,
							  false);
			if (ret != 0) {
				shell_error(sh, "Flash write failed: %d", ret);
				break;
			}
			total_bytes += blk.payload_len;
		}

		if (block_num % 100 == 0) {
			shell_print(sh, "  %u KB downloaded",
				    (unsigned)(total_bytes / 1024));
		}

		if (!blk.has_block2 || !blk.more) {
			ret = 0;
			break;
		}

		block_num++;
	}

	if (ret == 0) {
		ret = stream_flash_buffered_write(&stream, NULL, 0, true);
	}

	flash_area_close(fa);
	nrfcloud_disconnect(&s);

	if (ret != 0) {
		shell_error(sh, "Download failed at block %u", block_num);
		return ret;
	}

	shell_print(sh, "Downloaded %u bytes (%u blocks)",
		    (unsigned)total_bytes, block_num + 1);

	ret = boot_request_upgrade(BOOT_UPGRADE_TEST);
	if (ret != 0) {
		shell_error(sh, "boot_request_upgrade failed: %d", ret);
		return ret;
	}

	shell_print(sh, "Rebooting to apply update...");
	sys_reboot(SYS_REBOOT_COLD);

	/* unreachable */
	return 0;
}

#endif /* CONFIG_MEMFAULT */

/* --- Shell registration --- */

SHELL_STATIC_SUBCMD_SET_CREATE(nrfcloud_sub,
	SHELL_CMD(jwt, NULL,
		"Generate ES256-signed JWT for nRF Cloud",
		cmd_nrfcloud_jwt),
	SHELL_CMD_ARG(time, NULL,
		"Set or show wall-clock time\n"
		"Usage: nrfcloud time [unix_timestamp]",
		cmd_nrfcloud_time, 1, 1),
	SHELL_CMD_ARG(sntp, NULL,
		"Sync time via SNTP over NAT64\n"
		"Usage: nrfcloud sntp [hostname]  (default: time.google.com)",
		cmd_nrfcloud_sntp, 1, 1),
	SHELL_CMD(connect, NULL,
		"Connect to nRF Cloud CoAP (DTLS + JWT auth + test message)",
		cmd_nrfcloud_connect),
#ifdef CONFIG_MEMFAULT
	SHELL_CMD(send_memfault, NULL,
		"Upload pending Memfault chunks via nRF Cloud CoAP proxy",
		cmd_nrfcloud_send_memfault),
	SHELL_CMD(ota_check, NULL,
		"Check Memfault for firmware updates",
		cmd_nrfcloud_ota_check),
	SHELL_CMD(ota, NULL,
		"Check, download, and apply firmware update from Memfault",
		cmd_nrfcloud_ota),
#endif
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(nrfcloud, &nrfcloud_sub, "nRF Cloud commands", NULL);
