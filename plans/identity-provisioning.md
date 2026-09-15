# Device identity provisioning

Replaces the compiled-in private key in `credentials.h` with a keypair
generated inside the device, certified through a CSR that the Matter DAC
vouches for.

## Why

`credentials.h` carries a raw P-256 scalar in the image. Every unit built from
that image shares one identity, the private key is in the repo and in every
binary, and there is no way to revoke a single device. Fine for a lab bring-up,
untenable for a fleet.

The obvious fix — generate keys on an HSM and inject them at manufacture — moves
the problem rather than solving it. The private key still exists outside the
device, on a fixture PC and in whatever handles it in between.

## Approach

```
Device                                  Factory fixture / CA
------                                  --------------------
psa_generate_key()                      (no internet needed at the line)
  P-256, persistent, NOT exportable
build PKCS#10 CSR
sign CSR with Matter DAC key  ────────►  verify CSR self-signature
emit DAC + PAI + signature               verify DAC signed this CSR
                                         verify DAC -> PAI -> PAA
                                         (PAA roots come from the DCL)
                                         sign CSR with product CA
                              ◄────────  issued certificate (optional)
                                         -> nRF Cloud onboarding CSV
```

The private half never leaves the device. The fixture only ever sees public
material.

### Why the DAC signature matters

A bare CSR proves nothing — anything that can open a serial port can emit one.
The CA needs evidence that the request came from genuine hardware.

Nordic Identity is one way to supply that evidence, and it does not exist on
short-range parts today. But every Matter device is *required* to ship a Device
Attestation Certificate: a per-device certificate, provisioned at manufacture,
chaining to a PAA root published on the Matter Distributed Compliance Ledger.
Signing the CSR with the DAC key reuses that mandatory credential as the
attestation, and the DCL supplies a publicly verifiable trust root.

The DAC private key is never exposed to this code. Matter's
`DeviceAttestationCredentialsProvider` owns it; `provisioning_attest()` only
asks it to sign.

## Files

| File | Role |
|---|---|
| `src/provisioning.h` | Public API |
| `src/provisioning.c` | PSA keygen, CSR construction, certificate storage |
| `src/provisioning_attest.cpp` | Matter DAC signing + DAC/PAI retrieval |
| `src/provisioning_shell.c` | `provision` command group for the fixture |
| `tools/provision.py` | Factory driver: verify, issue, onboard |

## Factory flow

Three commands added to a fixture pass that already programs firmware and
Matter factory data:

```
provision keygen
provision bundle CN=shade-000123,O=Acme
provision cert_begin / cert_data ... / cert_commit    (optional)
```

Driven end to end by:

```bash
tools/provision.py --port /dev/ttyACM0 \
  --device-id shade-000123 --org Acme \
  --ca ca.pem --ca-key ca-key.pem \
  --paa-dir ./paa-roots --csv onboard.csv
```

Bring-up check with no CA in the loop:

```bash
tools/provision.py --port /dev/ttyACM0 --device-id test-001 --dry-run
```

## Storing the certificate is optional

`dtls_transport.c` configures DTLS for **server authentication only** — it
verifies the nRF Cloud CA and presents no client certificate. Device
authentication is entirely the JWT signed by the device key.

So the issued certificate only has to travel *outward*, into nRF Cloud
onboarding. Writing it back (`--store-cert`) exists so firmware can report its
own expiry as a metric, and to leave the door open for mutual TLS later.

## Key protection

| | nRF52840 | nRF54L |
|---|---|---|
| Key storage | Trusted storage (encrypted ITS) | KMU hardware slots |
| CPU can read key | Effectively no, but not hardware-enforced | No — pushed straight to CRACEN |
| Perimeter | APPROTECT (glitch-bypass history) | KMU + TF-M isolation |
| Kconfig | default | `CONFIG_PROVISIONING_KEY_IN_KMU=y` |

The provisioning code is identical on both. Only the Kconfig changes.

On nRF52840 this is the same protection the Matter DAC private key already has
on that part — this adds no new category of exposure to a product that already
ships a DAC.

## Certificate lifetime

Certificates expire; motorised shades last 10–20 years. Left alone, this
surfaces as an entire production cohort going silent on the same day, years
after anyone remembers why.

`identity_cert_days_left` is reported on every heartbeat so it can be alerted on
years ahead. The same CSR flow re-run over the network is the renewal path.

## Kconfig

| Symbol | Default | Notes |
|---|---|---|
| `PROVISIONING` | n | Master switch |
| `PROVISIONING_PSA_KEY_ID` | `0x12345678` | Must not collide with Matter's key IDs |
| `PROVISIONING_KEY_IN_KMU` | n | nRF54L only |
| `PROVISIONING_FALLBACK_KEY` | y | **Set n for production** |
| `PROVISIONING_SHELL` | y | Consider n for production images |

`PROVISIONING_FALLBACK_KEY` lets units flashed before provisioning existed keep
reporting by importing the `credentials.h` key. With it enabled an unprovisioned
device still has a working identity — exactly the property a production image
must not have.

## Verify before relying on this

- `CONFIG_MBEDTLS_X509_CSR_WRITE_C` / `CONFIG_MBEDTLS_PEM_WRITE_C` exist as
  Kconfig symbols in this NCS version. If nrf_security does not expose them,
  set them through a custom mbedTLS config header instead.
- `mbedtls_pk_setup_opaque()` is available — it requires
  `MBEDTLS_USE_PSA_CRYPTO`.
- `PSA_KEY_LOCATION_CRACEN_KMU` spelling for the target NCS release; it has
  moved between versions.
- Persistent PSA keys survive reboot on the target board. This depends on the
  trusted storage backend being wired up, which differs between the `cpuapp`
  and `cpuapp/ns` variants.
- nRF Cloud onboarding CSV column order against your `nrf_cloud_onboard`.
