/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Device identity provisioning — on-die key generation + attested CSR.
 *
 * Replaces the compiled-in private key in credentials.h with a keypair that
 * is generated inside the device and never leaves it. The factory reads out a
 * PKCS#10 CSR, has it signed by the product CA, and onboards the resulting
 * certificate to nRF Cloud. Only the public half ever crosses the fixture.
 *
 *   Device                                  Factory fixture / CA
 *   ------                                  --------------------
 *   psa_generate_key()  (non-exportable)
 *   build PKCS#10 CSR
 *   sign CSR with Matter DAC key  ────────►  verify DAC chain -> PAI -> PAA
 *   emit DAC + PAI + signature               (PAA roots come from the DCL)
 *                                            sign CSR with product CA
 *                                 ◄────────  issued certificate (optional)
 *
 * The DAC signature is what makes this safe without Nordic Identity: the CSR
 * is bound to a per-device certificate that was provisioned at manufacture and
 * chains to a PAA root published on the Matter Distributed Compliance Ledger.
 * A CSR that does not carry a valid DAC signature is not a genuine device.
 *
 * Note: nRF Cloud CoAP authenticates with a JWT signed by this key, not with a
 * DTLS client certificate (see dtls_transport.c — server auth only). The issued
 * certificate therefore only has to travel *outward*, to nRF Cloud onboarding.
 * Storing it back on the device is optional and exists so firmware can report
 * its own expiry.
 */

#ifndef PROVISIONING_H_
#define PROVISIONING_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <psa/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A P-256 CSR with a short CN lands around 300 bytes DER. */
#define PROV_CSR_DER_MAX   512
/* A P-256 leaf certificate lands around 400-500 bytes DER. */
#define PROV_CERT_DER_MAX  640
/* Matter DAC/PAI certificates are size-bounded by the spec at 600 bytes. */
#define PROV_ATT_CERT_MAX  600
/* Matter attestation signatures are raw r||s over P-256. */
#define PROV_ATT_SIG_LEN   64

enum prov_state {
	PROV_STATE_UNPROVISIONED = 0, /* no device key exists */
	PROV_STATE_KEY_READY,         /* key generated, certificate not issued */
	PROV_STATE_PROVISIONED,       /* key generated and certificate stored */
};

/*
 * Load persisted state. Safe to call before the key exists.
 * Called automatically at SYS_INIT; exposed for tests.
 */
int provisioning_init(void);

enum prov_state provisioning_get_state(void);

/*
 * Generate the device identity keypair inside the device.
 *
 * The key is persistent and is created without PSA_KEY_USAGE_EXPORT, so there
 * is no API that can read the private half back out. Idempotent: returns
 * -EEXIST if a key is already present unless @force is true.
 */
int provisioning_generate_key(bool force);

/*
 * PSA key handle to sign nRF Cloud JWTs with.
 *
 * Returns the provisioned key when one exists. When it does not and
 * CONFIG_PROVISIONING_FALLBACK_KEY is enabled, imports the demo key from
 * credentials.h into a volatile slot so existing lab devices keep working.
 * Returns -ENOENT when neither is available.
 */
int provisioning_get_signing_key(psa_key_id_t *key_id);

/*
 * Build a PKCS#10 CSR for the provisioned key.
 *
 * @param subject  RFC 4514 subject, e.g. "CN=shade-000123,O=Acme".
 *                 NULL uses "CN=" CONFIG_MEMFAULT_NCS_DEVICE_ID.
 * Output is DER, written to the front of @der.
 */
int provisioning_build_csr(const char *subject,
			   uint8_t *der, size_t der_size, size_t *der_len);

/*
 * Sign @blob with the Matter Device Attestation Certificate private key.
 *
 * The DAC key stays inside Matter's DeviceAttestationCredentialsProvider — it
 * is never exposed here, we only ask it to sign. Output is a raw r||s P-256
 * signature (PROV_ATT_SIG_LEN bytes), matching Matter attestation conventions.
 * The verifier must convert to ASN.1 DER before handing it to OpenSSL.
 */
int provisioning_attest(const uint8_t *blob, size_t blob_len,
			uint8_t *sig, size_t sig_size, size_t *sig_len);

/* Matter DAC / PAI certificates in DER, for the verifier to build the chain. */
int provisioning_get_dac(uint8_t *der, size_t der_size, size_t *der_len);
int provisioning_get_pai(uint8_t *der, size_t der_size, size_t *der_len);

/* Persist / retrieve the certificate issued by the product CA. */
int provisioning_store_cert(const uint8_t *der, size_t der_len);
int provisioning_load_cert(uint8_t *der, size_t der_size, size_t *der_len);
int provisioning_erase(void);

/*
 * notAfter of the stored certificate as a Unix timestamp, 0 if unknown.
 *
 * A shade has a 10-20 year service life and certificates do not. Surfacing
 * this as a metric turns a silent fleet-wide expiry into something visible
 * years ahead of the outage.
 */
uint32_t provisioning_cert_not_after(void);

#ifdef __cplusplus
}
#endif

#endif /* PROVISIONING_H_ */
