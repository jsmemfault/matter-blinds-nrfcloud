/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Matter DAC attestation for the provisioning CSR.
 *
 * This is the piece that removes the dependency on Nordic Identity. Every
 * Matter device is required to ship a Device Attestation Certificate whose
 * private key was provisioned at manufacture and whose chain terminates at a
 * PAA root published on the Distributed Compliance Ledger. Signing the CSR
 * with that key proves to the CA that the request came from a genuine device
 * of a specific VID/PID, using credentials the product already had to carry.
 *
 * The DAC private key is never exposed here. Matter's
 * DeviceAttestationCredentialsProvider owns it; we only ask it to sign.
 */

#include "provisioning.h"

#include <credentials/DeviceAttestationCredsProvider.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/support/Span.h>

#include <zephyr/logging/log.h>

#include <errno.h>
#include <string.h>

LOG_MODULE_DECLARE(provisioning, LOG_LEVEL_INF);

using chip::ByteSpan;
using chip::MutableByteSpan;
using chip::Credentials::DeviceAttestationCredentialsProvider;
using chip::Credentials::GetDeviceAttestationCredentialsProvider;

namespace {

enum class CertKind { kDac, kPai };

int CopyOutCert(CertKind kind, uint8_t *der, size_t der_size, size_t *der_len)
{
	DeviceAttestationCredentialsProvider *provider =
		GetDeviceAttestationCredentialsProvider();

	if (provider == nullptr) {
		LOG_ERR("no device attestation credentials provider");
		return -ENODEV;
	}

	if (der == nullptr || der_len == nullptr) {
		return -EINVAL;
	}

	uint8_t scratch[PROV_ATT_CERT_MAX];
	MutableByteSpan span(scratch);

	CHIP_ERROR err = (kind == CertKind::kDac)
				 ? provider->GetDeviceAttestationCert(span)
				 : provider->GetProductAttestationIntermediateCert(span);

	if (err != CHIP_NO_ERROR) {
		LOG_ERR("attestation cert fetch failed: %" CHIP_ERROR_FORMAT,
			err.Format());
		return -EIO;
	}

	if (span.size() > der_size) {
		return -ENOMEM;
	}

	memcpy(der, span.data(), span.size());
	*der_len = span.size();
	return 0;
}

} /* namespace */

extern "C" int provisioning_attest(const uint8_t *blob, size_t blob_len,
				   uint8_t *sig, size_t sig_size, size_t *sig_len)
{
	DeviceAttestationCredentialsProvider *provider =
		GetDeviceAttestationCredentialsProvider();

	if (provider == nullptr) {
		LOG_ERR("no device attestation credentials provider");
		return -ENODEV;
	}

	if (blob == nullptr || sig == nullptr || sig_len == nullptr) {
		return -EINVAL;
	}

	if (sig_size < PROV_ATT_SIG_LEN) {
		return -ENOMEM;
	}

	/*
	 * Matter emits a raw r||s P-256 signature, not ASN.1 DER. The factory
	 * verifier must re-encode before handing it to OpenSSL — tools/provision.py
	 * does this in _raw_sig_to_der().
	 */
	uint8_t scratch[chip::Crypto::kMax_ECDSA_Signature_Length];
	MutableByteSpan span(scratch);

	CHIP_ERROR err = provider->SignWithDeviceAttestationKey(
		ByteSpan(blob, blob_len), span);

	if (err != CHIP_NO_ERROR) {
		LOG_ERR("SignWithDeviceAttestationKey failed: %" CHIP_ERROR_FORMAT,
			err.Format());
		return -EIO;
	}

	if (span.size() > sig_size) {
		return -ENOMEM;
	}

	memcpy(sig, span.data(), span.size());
	*sig_len = span.size();
	return 0;
}

extern "C" int provisioning_get_dac(uint8_t *der, size_t der_size, size_t *der_len)
{
	return CopyOutCert(CertKind::kDac, der, der_size, der_len);
}

extern "C" int provisioning_get_pai(uint8_t *der, size_t der_size, size_t *der_len)
{
	return CopyOutCert(CertKind::kPai, der, der_size, der_len);
}
