/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CSR_H_
#define CSR_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <psa/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal PKCS#10 (RFC 2986) certificate request writer for P-256 keys held in
 * PSA.
 *
 * This exists instead of mbedtls_x509write_csr() deliberately. That API needs
 * mbedtls_pk_setup_opaque() to bind a non-exportable PSA key to a CSR context,
 * and mbedTLS 4.x — shipped from NCS 3.4.0 — removed the public PK module
 * entirely in favour of PSA. Rather than track that churn, we emit the ~300
 * bytes of DER directly: the private key never leaves PSA, and the only
 * dependency is psa_sign_message() plus psa_export_public_key().
 *
 * Matter's own GenerateCertificateSigningRequest() is not usable here either —
 * it hardcodes the subject to "OU=CSA" because its CA assigns the identity. We
 * need CN to carry the device ID so the issued certificate matches the JWT
 * "sub" claim that nRF Cloud keys on.
 *
 * Structures emitted (RFC 2986 §4):
 *
 *   CertificationRequest ::= SEQUENCE {
 *       certificationRequestInfo CertificationRequestInfo,
 *       signatureAlgorithm       AlgorithmIdentifier,
 *       signature                BIT STRING }
 *
 *   CertificationRequestInfo ::= SEQUENCE {
 *       version       INTEGER (0),
 *       subject       Name,
 *       subjectPKInfo SubjectPublicKeyInfo,
 *       attributes    [0] IMPLICIT SET OF Attribute }
 */

/*
 * Build a DER-encoded PKCS#10 CSR for @key_id, signed with ECDSA-SHA256.
 *
 * @param key_id   PSA key handle. Must allow PSA_KEY_USAGE_SIGN_MESSAGE; the
 *                 private half is never exported.
 * @param subject  RFC 4514-style subject. Only CN=, O= and OU= are recognised,
 *                 comma-separated, no value escaping. e.g. "CN=shade-000123,O=Acme".
 * @param der      Output buffer; DER is written to the front.
 * @param der_size Size of @der. 512 bytes is ample for a short subject.
 * @param der_len  Bytes written.
 *
 * @return 0 on success, negative errno on failure.
 */
int csr_write_der(psa_key_id_t key_id, const char *subject,
		  uint8_t *der, size_t der_size, size_t *der_len);

#ifdef __cplusplus
}
#endif

#endif /* CSR_H_ */
