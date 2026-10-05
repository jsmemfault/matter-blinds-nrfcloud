# Migrating to NCS 3.4.0 LTS

Notes from porting this integration from NCS 3.2.x/3.3.x to 3.4.0, verified by
building all four combinations (nRF52840 and nRF5340, on 3.2.4 and 3.4.0).

## One root cause

**NCS 3.4.0 ships mbedTLS 4.1.0**, up from 3.x. mbedTLS 4.x is PSA-native and
**removed the public PK module** — there is no `mbedtls/pk.h`. Five of the eight
changes below follow from that single fact.

If your firmware only reaches crypto through PSA, you are largely unaffected.
If it does X.509 or TLS work directly against mbedTLS, that is where the effort
lands.

## The changes

| # | Change | What to do |
|---|---|---|
| 1 | `MBEDTLS_TLS_LIBRARY` became promptless | Assigning it in `prj.conf` is now a **hard Kconfig error**. It is `select`ed only by `OPENTHREAD_JOINER \| COMMISSIONER \| COAPS \| BLE_TCAT`, by Wi-Fi's hostap_crypto, or `NET_SOCKETS_SOCKOPT_TLS`. If none apply, give it `default y` in your own Kconfig, which is parsed before the sourced NCS files. |
| 2 | `mbedtls_pk_setup_opaque()` removed | No way to bind a non-exportable PSA key to mbedTLS X.509 writing. See *CSR generation* below. |
| 3 | `mbedtls_x509write_csr_der()` signature changed | RNG parameters dropped (`ctx, buf, size` only). |
| 4 | `mbedtls_ssl_conf_rng()` absent under `MBEDTLS_USE_PSA_CRYPTO` | The SSL layer draws randomness from PSA. Guard the call and its callback. |
| 5 | `mbedtls/entropy.h` not exposed | Drop the include; any non-zero return signals failure to an mbedTLS RNG callback. |
| 6 | Matter factory data moved to devicetree | `pm_static_*.yml` is replaced by `#include <samples/matter/nrf52840_partitions.dtsi>` (or `nrf5340_cpuapp_partitions.dtsi`), plus `SB_CONFIG_PARTITION_MANAGER=n`. Addresses are unchanged. |
| 7 | PM partition names gone | Anything using `FIXED_PARTITION_ID(mcuboot_secondary)` needs `slot1_partition` when Partition Manager is off. Same region. |
| 8 | nRF5340 needs a `b0n` image config | With `SECURE_BOOT_NETCORE`, sysbuild builds four images and the network-core bootloader needs `sysbuild/b0n/prj.conf` plus a cpunet overlay setting `zephyr,code-partition = &b0n_partition`. |

## CSR generation

This project previously used `mbedtls_x509write_csr()` with
`mbedtls_pk_setup_opaque()` to sign a CSR with a key that never leaves PSA.
That is not possible on mbedTLS 4.x.

Two alternatives were rejected:

- **Matter's `GenerateCertificateSigningRequest()`** hardcodes the subject to
  `OU=CSA` ("Any subject, placeholder is good, since this is going to usually be
  ignored"), because Matter's CA assigns the identity. We need `CN` to carry the
  device ID so the issued certificate matches the JWT `sub` claim.
- **Subclassing `P256Keypair`** to reuse Matter's ASN.1 writer works, but
  depends on Matter internals, and `P256Keypair::Clear()` calls
  `psa_destroy_key()` — a subclass holding a persistent provisioned key would
  destroy the device identity on destruction.

So `src/csr.c` emits the ~230 bytes of PKCS#10 DER directly. It needs only
`psa_export_public_key()` and `psa_sign_message()`, which makes it immune to
this class of churn, and it **removed six mbedTLS Kconfig selects**
(`X509_CSR_WRITE_C`, `X509_CREATE_C`, `OID_C`, `ASN1_WRITE_C`, `PK_PARSE_C`,
`PK_WRITE_C`).

## Measured result — the migration shrank the image

Same source, nRF52840:

| NCS | Flash | | RAM | |
|---|---:|---:|---:|---:|
| 3.2.4 | 875,856 B | 89.14% | 226,300 B | 86.33% |
| **3.4.0 LTS** | **865,796 B** | 88.83% | **224,740 B** | 85.73% |

nRF5340 app core on 3.4.0: 800,316 B flash (81.79%), 236,936 B RAM (**52.59%**) —
far more RAM headroom than the 52840.

## nRF5340 is a four-image build

MCUboot, the application on cpuapp, `ipc_radio` on cpunet, and **B0N** (the
network-core secure bootloader). The partition layout carries both
`mcuboot_secondary` and `mcuboot_secondary_1` in external flash, so an OTA has
to account for network-core firmware alongside the application.

## Not yet verified on hardware

`src/csr.c` is validated on the host — OpenSSL parses the output, the subject and
embedded public key are correct, and the signed byte range matches RFC 2986's
`CertificationRequestInfo`. The real PSA signature path has not been exercised
on a device. `tools/provision.py --dry-run` checks it end to end.
