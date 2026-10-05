/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Minimal PKCS#10 CSR writer. See csr.h for why this is hand-rolled rather
 * than using mbedtls_x509write_csr() or Matter's CSR generator.
 *
 * DER is built innermost-first into small stack buffers, then wrapped. A P-256
 * CSR with a short subject lands around 300 bytes, so nothing here needs the
 * heap.
 */

#include "csr.h"

#include <zephyr/logging/log.h>

#include <string.h>
#include <errno.h>

LOG_MODULE_REGISTER(csr, LOG_LEVEL_INF);

/* ASN.1 tags */
#define ASN1_INTEGER      0x02
#define ASN1_BIT_STRING   0x03
#define ASN1_OID          0x06
#define ASN1_UTF8_STRING  0x0C
#define ASN1_SEQUENCE     0x30
#define ASN1_SET          0x31
#define ASN1_CTX0         0xA0  /* [0] constructed */

/* 1.2.840.10045.2.1 id-ecPublicKey */
static const uint8_t oid_ec_pubkey[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
/* 1.2.840.10045.3.1.7 prime256v1 */
static const uint8_t oid_prime256v1[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
/* 1.2.840.10045.4.3.2 ecdsa-with-SHA256 */
static const uint8_t oid_ecdsa_sha256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
/* 2.5.4.3 commonName, 2.5.4.10 organizationName, 2.5.4.11 organizationalUnitName */
static const uint8_t oid_cn[] = { 0x55, 0x04, 0x03 };
static const uint8_t oid_o[]  = { 0x55, 0x04, 0x0A };
static const uint8_t oid_ou[] = { 0x55, 0x04, 0x0B };

/* --- DER primitives --- */

/* Bytes needed to encode a definite length. */
static size_t der_len_bytes(size_t len)
{
	if (len < 0x80) {
		return 1;
	}
	if (len <= 0xFF) {
		return 2;
	}
	return 3; /* nothing here exceeds 64 KiB */
}

static int der_put_len(uint8_t *out, size_t out_size, size_t *pos, size_t len)
{
	size_t need = der_len_bytes(len);

	if (*pos + need > out_size) {
		return -ENOMEM;
	}

	if (len < 0x80) {
		out[(*pos)++] = (uint8_t)len;
	} else if (len <= 0xFF) {
		out[(*pos)++] = 0x81;
		out[(*pos)++] = (uint8_t)len;
	} else {
		out[(*pos)++] = 0x82;
		out[(*pos)++] = (uint8_t)(len >> 8);
		out[(*pos)++] = (uint8_t)(len & 0xFF);
	}

	return 0;
}

/* Append tag + length + value. */
static int der_tlv(uint8_t *out, size_t out_size, size_t *pos,
		   uint8_t tag, const uint8_t *val, size_t len)
{
	if (*pos + 1 > out_size) {
		return -ENOMEM;
	}

	out[(*pos)++] = tag;

	if (der_put_len(out, out_size, pos, len) != 0) {
		return -ENOMEM;
	}

	if (*pos + len > out_size) {
		return -ENOMEM;
	}

	if (len != 0) {
		memcpy(out + *pos, val, len);
		*pos += len;
	}

	return 0;
}

/* --- Subject (RFC 4514 subset) --- */

static const uint8_t *attr_oid(const char *name, size_t name_len, size_t *oid_len)
{
	if (name_len == 2 && strncmp(name, "CN", 2) == 0) {
		*oid_len = sizeof(oid_cn);
		return oid_cn;
	}
	if (name_len == 1 && name[0] == 'O') {
		*oid_len = sizeof(oid_o);
		return oid_o;
	}
	if (name_len == 2 && strncmp(name, "OU", 2) == 0) {
		*oid_len = sizeof(oid_ou);
		return oid_ou;
	}
	return NULL;
}

/*
 * Encode a Name: SEQUENCE OF SET OF SEQUENCE { OID, UTF8String }.
 * One RDN per comma-separated component, in the order given.
 */
static int encode_subject(const char *subject, uint8_t *out, size_t out_size,
			  size_t *out_len)
{
	uint8_t rdns[256];
	size_t rdns_pos = 0;
	const char *p = subject;

	while (*p != '\0') {
		const char *comma = strchr(p, ',');
		size_t comp_len = comma ? (size_t)(comma - p) : strlen(p);
		const char *eq = memchr(p, '=', comp_len);

		if (eq == NULL) {
			LOG_ERR("subject component has no '=': %.*s", (int)comp_len, p);
			return -EINVAL;
		}

		size_t name_len = (size_t)(eq - p);
		const char *val = eq + 1;
		size_t val_len = comp_len - name_len - 1;
		size_t oid_len;
		const uint8_t *oid = attr_oid(p, name_len, &oid_len);

		if (oid == NULL) {
			LOG_ERR("unsupported subject attribute '%.*s' "
				"(only CN, O, OU)", (int)name_len, p);
			return -EINVAL;
		}

		/* SEQUENCE { OID, UTF8String } */
		uint8_t atv[160];
		size_t atv_pos = 0;

		if (der_tlv(atv, sizeof(atv), &atv_pos, ASN1_OID, oid, oid_len) != 0 ||
		    der_tlv(atv, sizeof(atv), &atv_pos, ASN1_UTF8_STRING,
			    (const uint8_t *)val, val_len) != 0) {
			return -ENOMEM;
		}

		uint8_t atv_seq[176];
		size_t atv_seq_pos = 0;

		if (der_tlv(atv_seq, sizeof(atv_seq), &atv_seq_pos,
			    ASN1_SEQUENCE, atv, atv_pos) != 0) {
			return -ENOMEM;
		}

		/* SET { .. } , appended to the Name body */
		if (der_tlv(rdns, sizeof(rdns), &rdns_pos,
			    ASN1_SET, atv_seq, atv_seq_pos) != 0) {
			return -ENOMEM;
		}

		if (comma == NULL) {
			break;
		}
		p = comma + 1;
	}

	if (rdns_pos == 0) {
		LOG_ERR("empty subject");
		return -EINVAL;
	}

	*out_len = 0;
	return der_tlv(out, out_size, out_len, ASN1_SEQUENCE, rdns, rdns_pos);
}

/* --- Signature conversion --- */

/*
 * PSA returns a raw r||s pair; DER wants SEQUENCE { INTEGER r, INTEGER s }
 * with each integer minimally encoded and a leading 0x00 when the high bit
 * is set (so it is not read as negative).
 */
static int der_int(uint8_t *out, size_t out_size, size_t *pos,
		   const uint8_t *val, size_t len)
{
	size_t lead = 0;

	while (lead < len - 1 && val[lead] == 0x00) {
		lead++;
	}

	const uint8_t *v = val + lead;
	size_t vlen = len - lead;
	bool pad = (v[0] & 0x80) != 0;

	if (*pos + 2 + pad + vlen > out_size) {
		return -ENOMEM;
	}

	out[(*pos)++] = ASN1_INTEGER;
	out[(*pos)++] = (uint8_t)(vlen + pad);

	if (pad) {
		out[(*pos)++] = 0x00;
	}

	memcpy(out + *pos, v, vlen);
	*pos += vlen;

	return 0;
}

static int raw_sig_to_der(const uint8_t *raw, size_t raw_len,
			  uint8_t *out, size_t out_size, size_t *out_len)
{
	if (raw_len != 64) {
		LOG_ERR("expected 64-byte raw signature, got %zu", raw_len);
		return -EINVAL;
	}

	uint8_t ints[80];
	size_t ints_pos = 0;

	if (der_int(ints, sizeof(ints), &ints_pos, raw, 32) != 0 ||
	    der_int(ints, sizeof(ints), &ints_pos, raw + 32, 32) != 0) {
		return -ENOMEM;
	}

	*out_len = 0;
	return der_tlv(out, out_size, out_len, ASN1_SEQUENCE, ints, ints_pos);
}

/* --- CSR --- */

int csr_write_der(psa_key_id_t key_id, const char *subject,
		  uint8_t *der, size_t der_size, size_t *der_len)
{
	if (subject == NULL || der == NULL || der_len == NULL) {
		return -EINVAL;
	}

	/* Public key: uncompressed point, 0x04 || X || Y */
	uint8_t pubkey[65];
	size_t pubkey_len;
	psa_status_t status = psa_export_public_key(key_id, pubkey, sizeof(pubkey),
						    &pubkey_len);

	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_export_public_key failed: %d", (int)status);
		return -EIO;
	}

	/* SubjectPublicKeyInfo */
	uint8_t algid[32];
	size_t algid_pos = 0;

	if (der_tlv(algid, sizeof(algid), &algid_pos, ASN1_OID,
		    oid_ec_pubkey, sizeof(oid_ec_pubkey)) != 0 ||
	    der_tlv(algid, sizeof(algid), &algid_pos, ASN1_OID,
		    oid_prime256v1, sizeof(oid_prime256v1)) != 0) {
		return -ENOMEM;
	}

	uint8_t bitstr[72];
	size_t bitstr_pos = 0;

	bitstr[bitstr_pos++] = 0x00; /* unused bits */
	if (bitstr_pos + pubkey_len > sizeof(bitstr)) {
		return -ENOMEM;
	}
	memcpy(bitstr + bitstr_pos, pubkey, pubkey_len);
	bitstr_pos += pubkey_len;

	uint8_t spki_body[128];
	size_t spki_body_pos = 0;

	if (der_tlv(spki_body, sizeof(spki_body), &spki_body_pos,
		    ASN1_SEQUENCE, algid, algid_pos) != 0 ||
	    der_tlv(spki_body, sizeof(spki_body), &spki_body_pos,
		    ASN1_BIT_STRING, bitstr, bitstr_pos) != 0) {
		return -ENOMEM;
	}

	/* Subject */
	uint8_t subj[288];
	size_t subj_len;
	int ret = encode_subject(subject, subj, sizeof(subj), &subj_len);

	if (ret != 0) {
		return ret;
	}

	/* CertificationRequestInfo */
	uint8_t cri_body[448];
	size_t cri_body_pos = 0;
	const uint8_t zero = 0x00;

	if (der_tlv(cri_body, sizeof(cri_body), &cri_body_pos,
		    ASN1_INTEGER, &zero, 1) != 0) {
		return -ENOMEM;
	}
	if (cri_body_pos + subj_len > sizeof(cri_body)) {
		return -ENOMEM;
	}
	memcpy(cri_body + cri_body_pos, subj, subj_len);
	cri_body_pos += subj_len;

	if (der_tlv(cri_body, sizeof(cri_body), &cri_body_pos,
		    ASN1_SEQUENCE, spki_body, spki_body_pos) != 0 ||
	    /* attributes [0] — empty */
	    der_tlv(cri_body, sizeof(cri_body), &cri_body_pos,
		    ASN1_CTX0, NULL, 0) != 0) {
		return -ENOMEM;
	}

	uint8_t cri[464];
	size_t cri_len = 0;

	if (der_tlv(cri, sizeof(cri), &cri_len, ASN1_SEQUENCE,
		    cri_body, cri_body_pos) != 0) {
		return -ENOMEM;
	}

	/* Sign the CertificationRequestInfo exactly as encoded. */
	uint8_t raw_sig[64];
	size_t raw_sig_len;

	status = psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				  cri, cri_len, raw_sig, sizeof(raw_sig),
				  &raw_sig_len);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_sign_message failed: %d", (int)status);
		return -EIO;
	}

	uint8_t sig_der[80];
	size_t sig_der_len;

	ret = raw_sig_to_der(raw_sig, raw_sig_len, sig_der, sizeof(sig_der),
			     &sig_der_len);
	if (ret != 0) {
		return ret;
	}

	/* CertificationRequest */
	uint8_t sig_alg[16];
	size_t sig_alg_pos = 0;
	uint8_t sig_alg_body[16];
	size_t sig_alg_body_pos = 0;

	if (der_tlv(sig_alg_body, sizeof(sig_alg_body), &sig_alg_body_pos,
		    ASN1_OID, oid_ecdsa_sha256, sizeof(oid_ecdsa_sha256)) != 0 ||
	    der_tlv(sig_alg, sizeof(sig_alg), &sig_alg_pos, ASN1_SEQUENCE,
		    sig_alg_body, sig_alg_body_pos) != 0) {
		return -ENOMEM;
	}

	uint8_t sig_bits[88];
	size_t sig_bits_pos = 0;

	sig_bits[sig_bits_pos++] = 0x00;
	if (sig_bits_pos + sig_der_len > sizeof(sig_bits)) {
		return -ENOMEM;
	}
	memcpy(sig_bits + sig_bits_pos, sig_der, sig_der_len);
	sig_bits_pos += sig_der_len;

	uint8_t body[576];
	size_t body_pos = 0;

	if (cri_len > sizeof(body)) {
		return -ENOMEM;
	}
	memcpy(body, cri, cri_len);
	body_pos = cri_len;

	if (body_pos + sig_alg_pos > sizeof(body)) {
		return -ENOMEM;
	}
	memcpy(body + body_pos, sig_alg, sig_alg_pos);
	body_pos += sig_alg_pos;

	if (der_tlv(body, sizeof(body), &body_pos, ASN1_BIT_STRING,
		    sig_bits, sig_bits_pos) != 0) {
		return -ENOMEM;
	}

	*der_len = 0;
	return der_tlv(der, der_size, der_len, ASN1_SEQUENCE, body, body_pos);
}
