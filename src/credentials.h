/*
 * Copyright (c) 2026 Jon Sharp
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CREDENTIALS_H_
#define CREDENTIALS_H_

#include <stdint.h>

/*
 * Device identity for nRF Cloud CoAP.
 *
 * nRF Cloud authenticates the device with an ES256 JWT whose "sub" claim is
 * DEVICE_ID, signed by the device's private key. The DTLS session itself is
 * server-authenticated only (see dtls_transport.c) — the device presents no
 * client certificate, so no device certificate is needed on-device at all.
 *
 * With CONFIG_PROVISIONING=y the signing key is generated inside the device
 * and never leaves it, and this file supplies only DEVICE_ID and the nRF Cloud
 * root CA. See plans/identity-provisioning.md.
 *
 * The private_key[] below exists solely for CONFIG_PROVISIONING_FALLBACK_KEY,
 * which is off by default. It is deliberately all zeroes: a compiled-in device
 * key means every unit built from the image shares one identity and the key is
 * in the repository and in every binary. Do not put a real key here.
 */

#define DEVICE_ID CONFIG_MEMFAULT_NCS_DEVICE_ID

/* EC P-256 private key (raw 32-byte scalar, big-endian).
 *
 * Only referenced when CONFIG_PROVISIONING_FALLBACK_KEY=y. Prefer on-die key
 * generation (CONFIG_PROVISIONING=y) over filling this in.
 */
static const uint8_t private_key[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* nRF Cloud CoAP root CA certificate (PEM) — public material.
 * CN=nRF Cloud, ECDSA P-256, self-signed, valid until 2048.
 * Source: nrf/subsys/net/lib/nrf_provisioning/src/cert_coap_root_ca.c
 */
static const char nrfcloud_ca_cert[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBjzCCATagAwIBAgIUOEakGUS/7BfSlprkly7UK43ZAwowCgYIKoZIzj0EAwIw\n"
	"FDESMBAGA1UEAwwJblJGIENsb3VkMB4XDTIzMDUyNDEyMzUzMloXDTQ4MTIzMDEy\n"
	"MzUzMlowFDESMBAGA1UEAwwJblJGIENsb3VkMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
	"AQcDQgAEPVmJXT4TA1ljMcbPH0hxlzMDiPX73FHsdGM/6mqAwq9m2Nunr5/gTQQF\n"
	"MBUZJaQ/rUycLmrT8i+NZ0f/OzoFsKNmMGQwHQYDVR0OBBYEFGusC7QaV825v0Ci\n"
	"qEv2m1HhiScSMB8GA1UdIwQYMBaAFGusC7QaV825v0CiqEv2m1HhiScSMBIGA1Ud\n"
	"EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0cAMEQC\n"
	"IH/C3yf5aNFSFlm44CoP5P8L9aW/5woNrzN/kU5I+H38AiAwiHYlPclp25LgY8e2\n"
	"n7e2W/H1LXJ7S3ENDBwKUF4qyw==\n"
	"-----END CERTIFICATE-----\n";

#endif /* CREDENTIALS_H_ */
