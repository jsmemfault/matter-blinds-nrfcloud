/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Device identity provisioning — on-die key generation + attested CSR.
 * See provisioning.h for the flow and its rationale.
 */

#include "provisioning.h"

#ifdef CONFIG_PROVISIONING_FALLBACK_KEY
#include "credentials.h"
#endif

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <mbedtls/x509_crt.h>   /* certificate parsing, for expiry */

#include "csr.h"

#include <string.h>
#include <errno.h>

LOG_MODULE_REGISTER(provisioning, LOG_LEVEL_INF);

#define PROV_PSA_KEY_ID   ((psa_key_id_t)CONFIG_PROVISIONING_PSA_KEY_ID)
#define PROV_SETTINGS_ROOT "prov"
#define PROV_SETTINGS_CERT PROV_SETTINGS_ROOT "/cert"

static uint8_t s_cert[PROV_CERT_DER_MAX];
static size_t s_cert_len;
static psa_key_id_t s_fallback_key = PSA_KEY_ID_NULL;

/* --- Key management --- */

static bool key_exists(psa_key_id_t id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(id, &attr);

	psa_reset_key_attributes(&attr);
	return status == PSA_SUCCESS;
}

int provisioning_generate_key(bool force)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	psa_status_t status;

	if (key_exists(PROV_PSA_KEY_ID)) {
		if (!force) {
			return -EEXIST;
		}
		LOG_WRN("Destroying existing device key %u", PROV_PSA_KEY_ID);
		psa_destroy_key(PROV_PSA_KEY_ID);
		s_cert_len = 0;
		settings_delete(PROV_SETTINGS_CERT);
	}

	/*
	 * No PSA_KEY_USAGE_EXPORT: there is deliberately no API path that can
	 * read the private half back out, on any silicon. psa_export_public_key()
	 * is unaffected — public export never requires the usage flag.
	 */
	psa_set_key_usage_flags(&attr,
				PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_id(&attr, PROV_PSA_KEY_ID);

#ifdef CONFIG_PROVISIONING_KEY_IN_KMU
	/*
	 * nRF54L only. Places the key in hardware KMU slots, pushed directly to
	 * CRACEN and never readable by the CPU — the migration upgrade described
	 * in the provisioning design note. The location macro moved between NCS
	 * releases; confirm against your tree before enabling.
	 */
	psa_set_key_lifetime(&attr,
			     PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
				     PSA_KEY_PERSISTENCE_DEFAULT,
				     PSA_KEY_LOCATION_CRACEN_KMU));
#else
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
#endif

	status = psa_generate_key(&attr, &key_id);
	psa_reset_key_attributes(&attr);

	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_generate_key failed: %d", (int)status);
		return -EIO;
	}

	LOG_INF("Generated device identity key (id=%u, P-256, non-exportable)",
		(unsigned)key_id);
	return 0;
}

int provisioning_get_signing_key(psa_key_id_t *key_id)
{
	if (!key_id) {
		return -EINVAL;
	}

	if (key_exists(PROV_PSA_KEY_ID)) {
		*key_id = PROV_PSA_KEY_ID;
		return 0;
	}

#ifdef CONFIG_PROVISIONING_FALLBACK_KEY
	/*
	 * Lab devices flashed before provisioning existed still carry the demo
	 * key in credentials.h. Import it once into a volatile slot so they keep
	 * reporting. Production builds should set PROVISIONING_FALLBACK_KEY=n.
	 */
	if (s_fallback_key != PSA_KEY_ID_NULL) {
		*key_id = s_fallback_key;
		return 0;
	}

	{
		psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
		psa_status_t status;

		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
		psa_set_key_type(&attr,
				 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attr, 256);
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

		status = psa_import_key(&attr, private_key, sizeof(private_key),
					&s_fallback_key);
		psa_reset_key_attributes(&attr);

		if (status != PSA_SUCCESS) {
			LOG_ERR("fallback psa_import_key failed: %d", (int)status);
			return -EIO;
		}

		LOG_WRN("Using compiled-in fallback key — device is not provisioned");
		*key_id = s_fallback_key;
		return 0;
	}
#else
	return -ENOENT;   /* picolibc has no ENOKEY */
#endif
}

/* --- CSR --- */

int provisioning_build_csr(const char *subject,
			   uint8_t *der, size_t der_size, size_t *der_len)
{
	char subject_buf[96];
	int ret;

	if (!der || !der_len) {
		return -EINVAL;
	}

	if (!key_exists(PROV_PSA_KEY_ID)) {
		return -ENOENT;
	}

	if (!subject) {
		ret = snprintf(subject_buf, sizeof(subject_buf), "CN=%s",
			       CONFIG_MEMFAULT_NCS_DEVICE_ID);
		if (ret < 0 || ret >= (int)sizeof(subject_buf)) {
			return -ENAMETOOLONG;
		}
		subject = subject_buf;
	}

	/*
	 * csr.c emits the DER directly rather than going through
	 * mbedtls_x509write_csr(). That API needs mbedtls_pk_setup_opaque() to
	 * bind a non-exportable PSA key, and mbedTLS 4.x — shipped from NCS
	 * 3.4.0 — removed the public PK module in favour of PSA. The private
	 * key still never leaves PSA either way.
	 */
	return csr_write_der(PROV_PSA_KEY_ID, subject, der, der_size, der_len);
}

/* --- Certificate storage --- */

int provisioning_store_cert(const uint8_t *der, size_t der_len)
{
	int ret;

	if (!der || der_len == 0 || der_len > sizeof(s_cert)) {
		return -EINVAL;
	}

	/* Reject anything that is not a parseable certificate for this key. */
	{
		mbedtls_x509_crt crt;

		mbedtls_x509_crt_init(&crt);
		ret = mbedtls_x509_crt_parse_der(&crt, der, der_len);
		mbedtls_x509_crt_free(&crt);

		if (ret != 0) {
			LOG_ERR("certificate does not parse: -0x%04x", (unsigned)-ret);
			return -EINVAL;
		}
	}

	ret = settings_save_one(PROV_SETTINGS_CERT, der, der_len);
	if (ret != 0) {
		LOG_ERR("settings_save_one failed: %d", ret);
		return ret;
	}

	memcpy(s_cert, der, der_len);
	s_cert_len = der_len;

	LOG_INF("Stored device certificate (%zu bytes)", der_len);
	return 0;
}

int provisioning_load_cert(uint8_t *der, size_t der_size, size_t *der_len)
{
	if (!der || !der_len) {
		return -EINVAL;
	}
	if (s_cert_len == 0) {
		return -ENOENT;
	}
	if (der_size < s_cert_len) {
		return -ENOMEM;
	}

	memcpy(der, s_cert, s_cert_len);
	*der_len = s_cert_len;
	return 0;
}

int provisioning_erase(void)
{
	s_cert_len = 0;
	settings_delete(PROV_SETTINGS_CERT);

	if (key_exists(PROV_PSA_KEY_ID)) {
		psa_destroy_key(PROV_PSA_KEY_ID);
	}

	LOG_WRN("Provisioning state erased");
	return 0;
}

enum prov_state provisioning_get_state(void)
{
	if (!key_exists(PROV_PSA_KEY_ID)) {
		return PROV_STATE_UNPROVISIONED;
	}
	return s_cert_len ? PROV_STATE_PROVISIONED : PROV_STATE_KEY_READY;
}

/* --- Certificate expiry --- */

/* Days from 1970-01-01 for a civil date (Howard Hinnant's algorithm). */
static int64_t days_from_civil(int y, unsigned m, unsigned d)
{
	y -= (m <= 2);

	const int64_t era = (y >= 0 ? y : y - 399) / 400;
	const unsigned yoe = (unsigned)(y - era * 400);
	const unsigned doy = (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u;
	const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;

	return era * 146097 + (int64_t)doe - 719468;
}

uint32_t provisioning_cert_not_after(void)
{
	mbedtls_x509_crt crt;
	uint32_t result = 0;

	if (s_cert_len == 0) {
		return 0;
	}

	mbedtls_x509_crt_init(&crt);

	if (mbedtls_x509_crt_parse_der(&crt, s_cert, s_cert_len) == 0) {
		const mbedtls_x509_time *t = &crt.valid_to;
		int64_t days = days_from_civil(t->year, (unsigned)t->mon,
					       (unsigned)t->day);

		result = (uint32_t)(days * 86400 + t->hour * 3600 +
				    t->min * 60 + t->sec);
	}

	mbedtls_x509_crt_free(&crt);
	return result;
}

/* --- Settings integration --- */

static int prov_settings_set(const char *name, size_t len,
			     settings_read_cb read_cb, void *cb_arg)
{
	if (settings_name_steq(name, "cert", NULL)) {
		ssize_t n;

		if (len > sizeof(s_cert)) {
			LOG_ERR("stored cert too large (%zu bytes)", len);
			return -EINVAL;
		}

		n = read_cb(cb_arg, s_cert, len);
		if (n < 0) {
			return (int)n;
		}

		s_cert_len = (size_t)n;
		return 0;
	}

	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(provisioning, PROV_SETTINGS_ROOT, NULL,
			       prov_settings_set, NULL, NULL);

int provisioning_init(void)
{
	int ret;

	/* Idempotent — Matter also initialises settings. */
	ret = settings_subsys_init();
	if (ret != 0 && ret != -EALREADY) {
		LOG_ERR("settings_subsys_init failed: %d", ret);
		return ret;
	}

	ret = settings_load_subtree(PROV_SETTINGS_ROOT);
	if (ret != 0) {
		LOG_WRN("settings_load_subtree failed: %d", ret);
	}

	switch (provisioning_get_state()) {
	case PROV_STATE_PROVISIONED:
		LOG_INF("Device provisioned (cert %zu bytes, expires %u)",
			s_cert_len, provisioning_cert_not_after());
		break;
	case PROV_STATE_KEY_READY:
		LOG_INF("Device key present, certificate not yet issued");
		break;
	default:
		LOG_WRN("Device not provisioned — run 'provision keygen'");
		break;
	}

	return 0;
}

static int provisioning_sys_init(void)
{
	return provisioning_init();
}

/* After PSA crypto and the settings backend, before the telemetry thread. */
SYS_INIT(provisioning_sys_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
