#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <openthread.h>
#include <openthread/dataset.h>
#include <openthread/thread.h>
#include <openthread/ip6.h>

LOG_MODULE_REGISTER(thread_prov, LOG_LEVEL_INF);

/*
 * Thread network Operational Dataset (TLV hex) for developer auto-join.
 * Auto-provisions the device onto the Thread network at boot if no
 * active dataset is already configured. Skipped if dataset already set
 * (e.g. after normal Matter commissioning).
 *
 * ⚠️  NEVER commit a real dataset to a public repo — it contains the
 *     Thread Network Master Key which grants full network access.
 *
 * To get your dataset from an already-commissioned device:
 *   ot dataset active -x
 *
 * Requires CONFIG_SHELL_CMD_BUFF_SIZE=512 to paste via UART directly.
 */
#define THREAD_DATASET_HEX  "YOUR_THREAD_DATASET_HEX_HERE"

static uint8_t hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return 0;
}

static int hex_to_bytes(const char *hex, uint8_t *buf, size_t buf_len)
{
	size_t len = strlen(hex);

	if (len % 2 != 0 || len / 2 > buf_len) {
		return -EINVAL;
	}
	for (size_t i = 0; i < len / 2; i++) {
		buf[i] = (hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]);
	}
	return len / 2;
}

void thread_prov_auto_join(void)
{
	otInstance *instance = openthread_get_default_instance();

	if (!instance) {
		return;
	}

	openthread_mutex_lock();

	/* Skip if already configured */
	otOperationalDataset dataset;

	if (otDatasetGetActive(instance, &dataset) == OT_ERROR_NONE) {
		LOG_INF("Thread dataset already configured, skipping auto-join");
		openthread_mutex_unlock();
		return;
	}

	LOG_INF("No Thread dataset found, provisioning from built-in dataset");

	uint8_t tlv_buf[256];
	int tlv_len = hex_to_bytes(THREAD_DATASET_HEX, tlv_buf, sizeof(tlv_buf));

	if (tlv_len < 0) {
		LOG_ERR("Invalid dataset hex");
		openthread_mutex_unlock();
		return;
	}

	otOperationalDatasetTlvs tlvs;

	memcpy(tlvs.mTlvs, tlv_buf, tlv_len);
	tlvs.mLength = tlv_len;

	if (otDatasetSetActiveTlvs(instance, &tlvs) != OT_ERROR_NONE) {
		LOG_ERR("Failed to set Thread dataset");
		openthread_mutex_unlock();
		return;
	}

	otIp6SetEnabled(instance, true);

	if (otThreadSetEnabled(instance, true) != OT_ERROR_NONE) {
		LOG_ERR("Failed to start Thread");
		openthread_mutex_unlock();
		return;
	}

	LOG_INF("Thread auto-join initiated");
	openthread_mutex_unlock();
}
