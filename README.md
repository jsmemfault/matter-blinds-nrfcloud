# Smart Blinds — Matter-over-Thread observability on nRF52840

A Matter motorised window covering that reports fleet health to Memfault
through nRF Cloud's CoAP proxy — on an **nRF52840**, with no modem, no Zephyr IP
stack and no HTTP client.

It exists to answer a question Matter itself does not: *can a shipping
nRF52-class Matter product get observability data out through the consumer
border routers people actually own?*

Matter has no native telemetry. A device that misbehaves on one ecosystem and
not another is, today, invisible to the manufacturer. This is a working
reference for closing that gap on constrained, non-cellular silicon.

> **Status:** builds and runs on hardware; the provisioning chain is verified
> end to end on an nRF52840-DK. The Thread and nRF Cloud path is not yet
> exercised — see [Verified so far](#verified-so-far).
>
> **Licensing:** see [NOTICE.md](NOTICE.md). One set of inherited files has
> unresolved provenance and must be settled before this is made public.

## What this is

| Layer | Source |
|---|---|
| Window covering application | NCS `samples/matter/window_covering`, plus two hooks |
| Observability transport | `memfault/ncs-example-matter-over-thread`, extended |
| Device identity provisioning | On-die keygen + Matter DAC-attested CSR (original) |

See [NOTICE.md](NOTICE.md) for exact per-file provenance and licensing.

The transport ported to nRF52840 **unchanged** from an nRF54L original:
`dtls_transport.c`, `coap_codec.c`, `jwt.c`, `telemetry.c`, `nrfcloud_shell.c`.
Only `blinds.cpp` is specific to this device type.

```
Smart Shade (nRF52840, Thread MTD/SSED)
    │ IEEE 802.15.4 / Thread
    ▼
Any Thread Border Router  (Apple / Google / Amazon / Eero)
    │ IPv6 + NAT64
    ├──► nRF Cloud CoAP ──► Memfault chunk proxy ──► memfault.com
    └──► Matter controller (local)
```

## Why the metrics are the point

Matter has no native telemetry. A shipped shade that misbehaves on one
ecosystem and not another is, today, invisible.

This build reports 37 heartbeat metrics in three groups:

- **Connectivity** (`ot_*`, `matter_*`) — detached time, parent changes,
  partition changes, parent RSSI, CCA errors, CASE failures, subscription
  teardowns. These are the symptoms of border-router incompatibility.
- **Product** (`blinds_*`) — lift/tilt position, motion state, calibration
  status, motor actuations and stalls per interval.
- **Plumbing** (`identity_*`, `nrfcloud_*`, `time_sync_ok`) — is telemetry
  itself healthy, and will it still be healthy next year.

The field that makes the rest actionable is **`matter_admin_vendor_id`** — the
Vendor ID of the ecosystem that commissioned the device (0x1349 Apple, 0x6006
Google, 0x1217 Amazon, 0x1049 SmartThings). Pushed to Memfault as a device
attribute, it lets every metric above be sliced by ecosystem, so
*"p95 detached time is 4x worse on Google than Apple"* becomes a query rather
than a guess.

That is the point of the whole exercise. Thread and Matter diagnostics are only
diagnostic if you know which ecosystem produced them.

## Build

```bash
nrfutil sdk-manager toolchain launch --ncs-version v3.3.0 \
  --chdir /opt/nordic/ncs/v3.3.0 -- \
  west build -p -b nrf52840dk/nrf52840 \
  -d blinds-nrf52840/build blinds-nrf52840
```

Flash (nRF52840-DK over J-Link):

```bash
nrfutil sdk-manager toolchain launch --ncs-version v3.3.0 \
  --chdir /opt/nordic/ncs/v3.3.0 -- \
  west flash -d blinds-nrf52840/build --erase
```

### Memfault project key

`prj.conf` and `prj_release.conf` ship with a **placeholder** project key:

```
CONFIG_MEMFAULT_NCS_PROJECT_KEY="YOUR_MEMFAULT_PROJECT_KEY"
```

The real key is deliberately kept out of git. Set it locally before a run that
should actually reach Memfault — a build with the placeholder connects, uploads,
and has its chunks **rejected server-side**, which looks like a transport bug
and is not one. If `nrfcloud send_memfault` reports success but nothing appears
in the Memfault dashboard, check this first.

## Footprint on nRF52840

Measured on NCS v3.3.0, `nrf52840dk/nrf52840`, MTD/SSED sleepy device:

| Build | Flash | | RAM | |
|---|---:|---:|---:|---:|
| Pristine NCS `window_covering` | 758,628 B | 77.2% | 163,892 B | 62.5% |
| + observability + identity (debug) | 872,712 B | 88.8% | 227,132 B | 86.6% |
| **Production (`prj_release.conf`)** | **702,684 B** | **71.5%** | **195,324 B** | **74.5%** |

Isolating the observability cost from the loss of LTO (which Memfault's
`--wrap` fault hooking forces off):

| | Flash | RAM |
|---|---:|---:|
| Observability + identity | **+45 KB** | **+35 KB** |
| Identity provisioning alone | +10 KB | +1.3 KB |
| Disabling LTO | +54 KB | −1.9 KB |

The production image leaves 273 KB of flash and 65 KB of RAM free. Note that
disabling LTO costs more flash than the entire observability stack.

[`plans/nrf52840-port-notes.md`](plans/nrf52840-port-notes.md) has the full
breakdown, five porting findings with reproduction steps, and the open items.

## Verified so far

On an nRF52840-DK (PCA10056):

- on-die P-256 key generation, non-exportable, **persists across hardware
  reset, Matter factory reset, and a firmware update**
- PKCS#10 CSR signed by the Matter DAC; verifier confirms the DAC signed that
  exact CSR and chains to the PAI
- certificate issuance, chunked write-back, and expiry parsing exact to the
  second
- `identity_cert_days_left` present in a serialized Memfault chunk
- full factory pass in 10.2 s

**Not yet exercised:** the device has not been commissioned onto a Thread
network, so the DTLS handshake over a sleepy end device, the nRF Cloud CoAP
path, `matter_admin_vendor_id` and the `blinds_*` metrics are all unproven.
Energy cost per upload — the number that decides whether a battery product can
afford telemetry at all — is unmeasured.

## Device topology

Configured as an **MTD / SSED sleepy end device**, matching what a real
motorised shade is rather than what is convenient to develop against. This
matters: it is the harder case for a DTLS handshake, and it is the case that
has to work.

## Provisioning

The compiled-in key in `credentials.h` is a lab artifact. The production path
generates the identity keypair inside the device and has the Matter DAC vouch
for the CSR — see [`plans/identity-provisioning.md`](plans/identity-provisioning.md).

```bash
# Verify attestation without a CA in the loop
tools/provision.py --port /dev/ttyACM0 --device-id shade-000123 --dry-run

# Full factory pass
tools/provision.py --port /dev/ttyACM0 --device-id shade-000123 --org Acme \
  --ca ca.pem --ca-key ca-key.pem --paa-dir ./paa-roots --csv onboard.csv
```

## Shell

| Command | Purpose |
|---|---|
| `echo nat64 <msg>` | Does this border router route to the internet at all? |
| `nrfcloud sntp` | Wall-clock sync — a prerequisite for auth |
| `nrfcloud connect` | DTLS + JWT auth against nRF Cloud |
| `nrfcloud send_memfault` | Force a chunk upload |
| `provision status` | Identity state and certificate expiry |
| `provision bundle` | Emit an attested CSR |
| `mflt test heartbeat` | Force a metric snapshot |
| `matter` / `ot` | Matter and OpenThread CLIs |

`echo nat64` is the first thing to run against any new gateway — it separates
"the radio joined" from "traffic actually reaches the internet", which are very
different failure modes and the ones that vary most by vendor.
