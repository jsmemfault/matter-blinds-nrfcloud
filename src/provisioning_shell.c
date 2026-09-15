/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Factory fixture interface for device provisioning.
 *
 * Designed to be driven by tools/provision.py as extra steps in the fixture
 * pass that already programs firmware and Matter factory data — not as a new
 * manufacturing stage. A full pass is:
 *
 *   provision keygen
 *   provision bundle CN=shade-000123,O=Acme     -> CSR + DAC + PAI + signature
 *   provision cert_begin / cert_data ... / cert_commit   (optional)
 *
 * Certificates are moved in 64-character base64 chunks so nothing depends on
 * CONFIG_SHELL_CMD_BUFF_SIZE being raised.
 */

#include "provisioning.h"

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/base64.h>

#include <string.h>
#include <errno.h>

/* 48 raw bytes encode to exactly 64 base64 characters — no padding mid-stream. */
#define B64_LINE_RAW  48
#define B64_LINE_TEXT 65

static uint8_t s_incoming[PROV_CERT_DER_MAX];
static size_t s_incoming_len;
static bool s_incoming_open;

static void emit_b64(const struct shell *sh, const char *label,
		     const uint8_t *data, size_t len)
{
	shell_print(sh, "-----BEGIN %s-----", label);

	for (size_t off = 0; off < len; off += B64_LINE_RAW) {
		char line[B64_LINE_TEXT + 4];
		size_t chunk = MIN((size_t)B64_LINE_RAW, len - off);
		size_t olen = 0;

		if (base64_encode((uint8_t *)line, sizeof(line), &olen,
				  data + off, chunk) != 0) {
			shell_error(sh, "base64_encode failed");
			return;
		}

		line[olen] = '\0';
		shell_print(sh, "%s", line);
	}

	shell_print(sh, "-----END %s-----", label);
}

static int cmd_status(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	static const char *const names[] = {
		[PROV_STATE_UNPROVISIONED] = "UNPROVISIONED",
		[PROV_STATE_KEY_READY]     = "KEY_READY",
		[PROV_STATE_PROVISIONED]   = "PROVISIONED",
	};

	enum prov_state state = provisioning_get_state();
	uint8_t der[PROV_CERT_DER_MAX];
	size_t der_len;

	shell_print(sh, "state:      %s", names[state]);
	shell_print(sh, "psa key id: %u", (unsigned)CONFIG_PROVISIONING_PSA_KEY_ID);

	if (provisioning_load_cert(der, sizeof(der), &der_len) == 0) {
		shell_print(sh, "cert:       %zu bytes", der_len);
		shell_print(sh, "expires:    %u (unix)", provisioning_cert_not_after());
	} else {
		shell_print(sh, "cert:       none");
	}

	return 0;
}

static int cmd_keygen(const struct shell *sh, size_t argc, char **argv)
{
	bool force = (argc >= 2) && (strcmp(argv[1], "force") == 0);
	int ret = provisioning_generate_key(force);

	if (ret == -EEXIST) {
		shell_warn(sh, "Key already exists. Use 'keygen force' to replace it.");
		return 0;
	}
	if (ret != 0) {
		shell_error(sh, "keygen failed: %d", ret);
		return ret;
	}

	shell_print(sh, "OK: device key generated (non-exportable)");
	return 0;
}

static int cmd_bundle(const struct shell *sh, size_t argc, char **argv)
{
	const char *subject = (argc >= 2) ? argv[1] : NULL;

	uint8_t csr[PROV_CSR_DER_MAX];
	uint8_t cert[PROV_ATT_CERT_MAX];
	uint8_t sig[PROV_ATT_SIG_LEN];
	size_t csr_len, cert_len, sig_len;
	int ret;

	ret = provisioning_build_csr(subject, csr, sizeof(csr), &csr_len);
	if (ret != 0) {
		shell_error(sh, "CSR generation failed: %d "
				"(run 'provision keygen' first)", ret);
		return ret;
	}

	emit_b64(sh, "CERTIFICATE REQUEST", csr, csr_len);

	/*
	 * Attestation binds the CSR to the Matter DAC. Without it the CA has no
	 * way to tell a genuine device from anything else that can open a serial
	 * port, so treat failure here as fatal rather than emitting a bare CSR.
	 */
	ret = provisioning_attest(csr, csr_len, sig, sizeof(sig), &sig_len);
	if (ret != 0) {
		shell_error(sh, "DAC attestation failed: %d "
				"(is CONFIG_CHIP_FACTORY_DATA enabled?)", ret);
		return ret;
	}

	emit_b64(sh, "ATTESTATION SIGNATURE", sig, sig_len);

	ret = provisioning_get_dac(cert, sizeof(cert), &cert_len);
	if (ret != 0) {
		shell_error(sh, "DAC fetch failed: %d", ret);
		return ret;
	}
	emit_b64(sh, "DAC", cert, cert_len);

	ret = provisioning_get_pai(cert, sizeof(cert), &cert_len);
	if (ret != 0) {
		shell_error(sh, "PAI fetch failed: %d", ret);
		return ret;
	}
	emit_b64(sh, "PAI", cert, cert_len);

	return 0;
}

static int cmd_cert_begin(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	s_incoming_len = 0;
	s_incoming_open = true;

	shell_print(sh, "OK: ready for cert_data");
	return 0;
}

static int cmd_cert_data(const struct shell *sh, size_t argc, char **argv)
{
	size_t text_len;
	size_t olen = 0;
	int ret;

	if (!s_incoming_open) {
		shell_error(sh, "call cert_begin first");
		return -EPERM;
	}

	text_len = strlen(argv[1]);
	if ((text_len % 4) != 0) {
		shell_error(sh, "chunk must be a multiple of 4 base64 characters");
		return -EINVAL;
	}

	ret = base64_decode(s_incoming + s_incoming_len,
			    sizeof(s_incoming) - s_incoming_len, &olen,
			    (const uint8_t *)argv[1], text_len);
	if (ret != 0) {
		s_incoming_open = false;
		shell_error(sh, "base64_decode failed: %d", ret);
		return -EINVAL;
	}

	s_incoming_len += olen;
	return 0;
}

static int cmd_cert_commit(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	int ret;

	if (!s_incoming_open || s_incoming_len == 0) {
		shell_error(sh, "no certificate staged");
		return -EPERM;
	}

	ret = provisioning_store_cert(s_incoming, s_incoming_len);
	s_incoming_open = false;

	if (ret != 0) {
		shell_error(sh, "store failed: %d", ret);
		return ret;
	}

	shell_print(sh, "OK: stored %zu bytes, expires %u",
		    s_incoming_len, provisioning_cert_not_after());
	s_incoming_len = 0;
	return 0;
}

static int cmd_erase(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	provisioning_erase();
	shell_print(sh, "OK: erased");
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(provision_sub,
	SHELL_CMD(status, NULL,
		  "Show provisioning state", cmd_status),
	SHELL_CMD_ARG(keygen, NULL,
		      "Generate device key: keygen [force]", cmd_keygen, 1, 1),
	SHELL_CMD_ARG(bundle, NULL,
		      "Emit CSR + attestation: bundle [subject]", cmd_bundle, 1, 1),
	SHELL_CMD(cert_begin, NULL,
		  "Begin certificate upload", cmd_cert_begin),
	SHELL_CMD_ARG(cert_data, NULL,
		      "Append base64 certificate chunk", cmd_cert_data, 2, 0),
	SHELL_CMD(cert_commit, NULL,
		  "Store the uploaded certificate", cmd_cert_commit),
	SHELL_CMD(erase, NULL,
		  "Erase key and certificate (development only)", cmd_erase),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(provision, &provision_sub, "Device identity provisioning", NULL);
