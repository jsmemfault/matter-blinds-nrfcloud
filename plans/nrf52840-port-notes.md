# Porting the observability stack to nRF52840

Measured findings from moving the Memfault-over-nRF-Cloud-CoAP transport from
the nRF54L15 (`openevse-nrf54l15`) to an nRF52840-DK running the NCS Matter
`window_covering` sample.

Everything here is measured on **NCS v3.3.0**, board `nrf52840dk/nrf52840`,
toolchain `0c0f19d91c`. Nothing in this document is an estimate.

## Headline: it works, and RAM is the binding constraint

Configured as an **MTD / SSED sleepy end device** — the topology a real
motorised shade uses, not the convenient one.

| Build | Flash | | RAM | |
|---|---:|---:|---:|---:|
| Pristine `window_covering` (baseline) | 758,628 B | 77.2% | 163,892 B | 62.5% |
| **+ observability + identity provisioning** (lab) | **872,712 B** | **88.8%** | **227,132 B** | **86.6%** |
| Delta | **+114,084 B** (+111 KB) | +11.6pp | **+63,240 B** (+62 KB) | +24.1pp |
| Lab headroom remaining | 109,816 B (107 KB) | | 35,012 B (34 KB) | |
| **Production image** (`prj_release.conf`) | **702,684 B** | **71.5%** | **195,324 B** | **74.5%** |
| **Production headroom remaining** | **279,844 B (273 KB)** | | **66,820 B (65 KB)** | |

The middle row is the **debug** configuration, which carries the Matter shell,
OpenThread shell, Memfault shell, provisioning shell, UDP echo shell and
deferred logging. That is the tight build, and it is not what ships.

The **production image — full observability, coredumps, and on-die identity —
uses 71.5% of flash and 74.5% of RAM, leaving 273 KB and 65 KB free.** It is
smaller than the *pristine debug* sample because stripping five shells and the
logging subsystem recovers more than the observability stack costs.

Read that as the answer to "can we ship this on our current silicon": yes, with
roughly a quarter of both resources still in hand.

App slot is 959 KB because the MCUboot secondary lives in the external QSPI
part (`pm_static_nrf52840dk_nrf52840.yml`). Without external flash this does not
fit — and would not have fit before adding observability either.

### Our own code is a small part of it

| Module | text | data | bss |
|---|---:|---:|---:|
| `dtls_transport.c` | 3,631 | 100 | 6,257 |
| `nrfcloud_shell.c` | 3,853 | 4 | 8,208 |
| `udp_echo_shell.c` | 2,648 | 52 | 277 |
| `jwt.c` | 2,585 | 28 | 529 |
| `provisioning.c` | 2,488 | 4 | 648 |
| `provisioning_shell.c` | 2,141 | 0 | 645 |
| `telemetry.c` | 1,534 | 4 | 9,048 |
| `coap_codec.c` | 1,277 | 0 | 2 |
| `matter_metrics.cpp` | 467 | 4 | 12 |
| `provisioning_attest.cpp` | 457 | 0 | 0 |
| `blinds.cpp` | 370 | 0 | 8 |
| **Total** | **21,451** | **196** | **25,634** |

**21 KB of the 111 KB flash delta is our code.** The remaining ~90 KB is
libraries it pulls in — principally the mbedTLS SSL/DTLS layer and the X.509
write / PK parse / ASN.1 write machinery that CSR generation requires, neither
of which the baseline linked at all.

That distinction matters commercially: the cost is dominated by *which mbedTLS
features you turn on*, not by the amount of code written, so it is largely
fixed regardless of how much application-specific telemetry gets added later.

## Three porting differences from nRF54L

### 1. `OPENTHREAD_COAPS` is not available, and it was load-bearing

The nRF54L project reached its mbedTLS DTLS configuration via
`CONFIG_OPENTHREAD_COAPS=y`. On nRF52840 that is not an option: the prebuilt
MTD library exports **no `otCoapSecure*` symbols** at all.

```
nrfxlib/openthread/lib/nrf52840/softfp-float/v1.4/mtd/libopenthread-mtd.a
  → 0 otCoapSecure symbols
```

Worse, `OPENTHREAD_COAPS` was not merely a convenient bundle — it is the
**gate**. `nrf/subsys/net/openthread/Kconfig.defconfig` contains:

```
if !(OPENTHREAD_JOINER || OPENTHREAD_COMMISSIONER || OPENTHREAD_COAPS || OPENTHREAD_BLE_TCAT)
config MBEDTLS_SSL_CLI_C
	default n
config MBEDTLS_SSL_TLS_C
	default n
endif
```

`MBEDTLS_SSL_TLS_C` is **promptless**, so `prj.conf` cannot raise it — its value
comes purely from whichever `default` the parser reaches first. Setting
`CONFIG_MBEDTLS_SSL_CLI_C=y` in `prj.conf` produces a Kconfig warning
("assigned the value 'y' but got the value 'n'") and then a wall of
`undefined reference to mbedtls_ssl_*` at link time.

The fix is to define `default y` for both symbols in the application's own
`Kconfig`, which is parsed **before** the sourced NCS files:

```
config MBEDTLS_SSL_TLS_C
	default y

config MBEDTLS_SSL_CLI_C
	default y
```

This is cheaper and more honest than enabling OpenThread's CoAP-secure stack to
flip a flag — we never use OT's CoAP anyway, all traffic goes through the native
UDP API.

**Generalises beyond this project:** any NCS OpenThread application that wants a
general-purpose DTLS client, on any silicon, hits this. It is not nRF52-specific.

### 2. `MBEDTLS_X509_CSR_WRITE_C` has undocumented prerequisites

Enabling it alone fails the build at `check_config.h:1057`. The full chain
(`check_config.h:1034`) is:

```
MBEDTLS_X509_CSR_WRITE_C
  → MBEDTLS_X509_CREATE_C
      → MBEDTLS_OID_C
      → MBEDTLS_ASN1_WRITE_C
      → MBEDTLS_PK_PARSE_C
      → MBEDTLS_MD_C or MBEDTLS_USE_PSA_CRYPTO
```

All are `select`ed from `config PROVISIONING` so this cannot regress.
`MBEDTLS_PEM_WRITE_C` is deliberately **not** enabled — provisioning emits DER
and base64-encodes in the shell layer, so the PEM writer would be dead flash.

Both API assumptions from the original design note are confirmed present in
NCS v3.3.0: `mbedtls_pk_setup_opaque` and `mbedtls_x509write_csr_der` are in
the linked image.

### 3. Exactly one metric needed an MTD guard

Of the OpenThread APIs the metric set uses, only one is FTD-only:

| API | in MTD lib? |
|---|---|
| `otThreadGetMleCounters` | yes |
| `otThreadGetNextNeighborInfo` | yes |
| `otThreadGetParentInfo` | yes |
| `otThreadGetParentAverageRssi` | yes |
| `otLinkGetCounters` / `otLinkGetChannel` | yes |
| `otNat64SynthesizeIp6Address` | yes |
| `otDnsClientResolveIp4Address` | yes |
| **`otThreadGetRouterInfo`** | **no — FTD only** |

`ot_router_count` is therefore `#ifdef CONFIG_OPENTHREAD_FTD` and reports 0 on a
sleepy device. No loss: an MTD sees exactly one parent and has no view of the
router table. The parent-based metrics carry the signal in that topology.

**The important half of this finding is what is *not* on the list.** NAT64
prefix synthesis and the DNS64 client — the workaround for border routers like
Eero that do NAT64 but not DNS64 — are both present in the **nRF52840 MTD**
library. The DNS64 mitigation works on a sleepy, battery-class device on
current silicon.

## Hardware validation

Run on an nRF52840-DK (PCA10056, J-Link 1050211676), debug build, board
recovered first because APPROTECT was set — a fitting demonstration of the
key-at-rest perimeter described above.

**Resolved. The full provisioning chain works end to end on real silicon:**

| Step | Result |
|---|---|
| `provision status` on a fresh device | `UNPROVISIONED`, key id 305419896 |
| `provision keygen` | on-die P-256 key created, non-exportable |
| `provision bundle` | CSR + attestation signature + DAC + PAI emitted |
| DAC identity | `CN=Matter Dev DAC 0xFFF1/0x8010` → `Matter Dev PAI 0xFFF1` → `Matter Test PAA` |
| `provision.py` verifier | CSR self-signature valid, **DAC signed that exact CSR**, DAC→PAI chain valid |
| Certificate issuance + chunked write-back | 368-byte cert stored |
| Expiry parsing | reports 2102954981 for a cert with `notAfter=Aug 21 18:09:41 2036 GMT` — exact to the second |
| Metric serialization | heartbeat chunk contains `02 19 0e 41` = `identity_state=2`, `identity_cert_days_left=3649`, matching `(notAfter − now) / 86400` exactly |

Two persistence results, both confirmed by comparing the CSR public key
byte-for-byte before and after:

- **Persistent PSA keys survive a hardware pin reset.** `CONFIG_TRUSTED_STORAGE=y`
  with no TF-M does what it claims on this part. This was the largest open risk
  in the provisioning design and it is now closed.
- **The device identity survives a Matter factory reset.** `matter device
  factoryreset` clears Matter's own settings — fabrics, ACLs, Last Known Good
  Time — but leaves the trusted-storage ITS entries and the `prov/cert` settings
  key untouched. Same key, same certificate afterwards.

That second result matters commercially and is worth stating to a customer
directly: **if a homeowner decommissions the shade from their ecosystem, the
device does not lose its cloud identity.** It can be re-commissioned into a
different ecosystem and keep reporting, with no return to the factory and no
re-provisioning. Had it gone the other way, every factory reset in the field
would have permanently blinded a unit.

### Still not verified

The device was never commissioned onto a Thread network during this session
(`ot state` = `disabled`), so everything downstream of the radio remains
untested:

1. **DTLS handshake over an SSED.** With a 500 ms poll interval each handshake
   flight costs up to one poll period. Untested, and the energy cost per upload
   is the number that decides whether a battery product can afford this at all.
2. **The nRF Cloud CoAP path itself** — `nrfcloud connect`, JWT auth,
   chunk upload. Needs a commissioned device on a Thread network with a border
   router.
3. **`matter_admin_vendor_id`** — reads the fabric table, so it needs a real
   commissioning against a real ecosystem to return anything but 0.
4. **`blinds_*` metrics** — `blinds.cpp` reads live Matter attributes; only
   exercised meaningfully once a controller is driving the covering.

### Incidental findings

- `mflt metrics_dump` produces no output with `CONFIG_MEMFAULT_LOGGING_ENABLE=n`,
  because the Memfault SDK routes that command's output through its own log
  macros. Use `mflt export` to confirm serialization instead, or enable the
  option in lab builds. The command also takes **no** argument — the form
  `mflt metrics_dump heartbeat` documented in the nRF54L project does not exist.
- `tools/provision.py` needed a fix found only on hardware: its serial read loop
  scanned for the shell prompt as a complete line, but the Zephyr shell emits
  the prompt with ANSI cursor controls and no trailing newline, so it never
  arrived as one. Replaced with an idle-based read.

## Design items still worth acting on

Not blockers, but they should not be forgotten:

1. **System work queue blocking.** Heartbeat collection runs from
   `k_work_submit` on the system work queue (`K_WORK_DEFINE(s_metrics_timer_work,
   …)` in the Memfault Zephyr port). Both `blinds_get_data()` and
   `matter_metrics_collect()` take the CHIP stack lock from there. That is the
   correct thread — no deadlock — but it stalls sysworkq for as long as the CHIP
   thread holds the lock. A production build should collect on the CHIP thread
   via `ScheduleWork` and have the heartbeat read a cache.
2. **DTLS session resumption.** If the handshake proves expensive over an SSED,
   resumption or a longer upload interval is the lever. Measure before building.
3. **RAM at 86.6% in the debug build.** 34 KB free. Confirm no stack overflow
   under a real DTLS handshake with `CONFIG_MBEDTLS_HEAP_SIZE=20480`. The
   production build sits at 74.5% and is not a concern.

## Reduction levers, if RAM gets tight

In rough order of value per unit of effort:

- Drop the dev shells (measured in the variant table below)
- `MEMFAULT_RAM_BACKED_COREDUMP_SIZE` is already cut 8 KB → 4 KB versus the
  nRF54L project; a flash-backed coredump in the external QSPI removes it
  entirely
- `CONFIG_MBEDTLS_HEAP_SIZE=20480` — trim once the true handshake watermark is
  measured
- `MBEDTLS_SSL_IN_CONTENT_LEN=1500` is sized for nRF Cloud's server
  certificate chain; do not cut without re-testing the handshake
- `nrfcloud_shell.c` (8.2 KB bss) and `telemetry.c` (9.0 KB bss) hold the
  largest static buffers of our own code

## Build variants

All figures are the **application** image (MCUboot is a separate 24,892 B / 28 KB
image and does not change between variants).

| Variant | Config | Flash | | RAM | |
|---|---|---:|---:|---:|---:|
| Baseline | pristine `window_covering` | 758,628 B | 77.2% | 163,892 B | 62.5% |
| Observability only | `prj.conf` + `overlay-no-provisioning.conf` | 862,264 B | 87.8% | 225,852 B | 86.2% |
| Full (lab) | `prj.conf` | 872,712 B | 88.8% | 227,132 B | 86.6% |
| **Production** | `prj_release.conf` | **702,684 B** | **71.5%** | **195,324 B** | **74.5%** |

Derived costs:

| | Flash | RAM |
|---|---:|---:|
| Observability transport (DTLS + CoAP + JWT + Memfault + metrics) | +103,636 B (101 KB) | +61,960 B (60.5 KB) |
| **Identity provisioning on top** | **+10,448 B (10.2 KB)** | **+1,280 B (1.3 KB)** |
| Both | +114,084 B (111 KB) | +63,240 B (62 KB) |

**The identity module is nearly free.** On-die key generation plus DAC-attested
CSR costs 10 KB flash and 1.3 KB RAM, because `PK_PARSE_C`, `MD_C`, `OID_C` and
`ASN1_WRITE_C` are already linked by Matter and the DTLS layer — only the X.509
CSR writer is genuinely new. There is no cost argument for deferring it.

Reproduce:

```bash
# baseline
west build -p -b nrf52840dk/nrf52840 -d /tmp/base \
  $NCS/nrf/samples/matter/window_covering

# observability without identity
west build -p -b nrf52840dk/nrf52840 -d /tmp/noprov blinds-nrf52840 \
  -- -DEXTRA_CONF_FILE=overlay-no-provisioning.conf

# full lab build
west build -p -b nrf52840dk/nrf52840 -d /tmp/full blinds-nrf52840

# production build
west build -p -b nrf52840dk/nrf52840 -d /tmp/rel blinds-nrf52840 \
  -- -DFILE_SUFFIX=release
```

## Two things the release configuration forced

Neither of these shows up in a debug build, and both would have surfaced late.

### `CONFIG_LTO=y` is incompatible with Memfault coredump capture

**And losing LTO costs more flash than the entire observability stack.**

Isolating the two effects with a pristine-release build at `CONFIG_LTO=n`:

| Build | Flash | RAM |
|---|---:|---:|
| Pristine release, LTO **on** (stock sample) | 601,028 B | 161,076 B |
| Pristine release, LTO **off** | 656,180 B | 159,156 B |
| Ours: + observability + identity, LTO off | 702,684 B | 195,324 B |

| | Flash | RAM |
|---|---:|---:|
| Cost of disabling LTO | **+55,152 B (54 KB)** | −1,920 B |
| **Cost of observability + identity** | **+46,504 B (45 KB)** | **+36,168 B (35 KB)** |

Two things follow.

First, **45 KB flash / 35 KB RAM is the honest production cost of the
observability and identity stack** — and it lines up almost exactly with the
~48 KB / ~32 KB figure documented for the nRF54L build, which is a useful
independent check that neither measurement is wrong.

Second, the single largest flash cost of adding Memfault to this sample is not
Memfault — it is being forced to turn LTO off, at 54 KB. Fixing the
`--wrap`/LTO incompatibility in the Memfault Zephyr port would recover more
flash than the whole stack consumes. Worth raising with Memfault.



The NCS `window_covering` release config enables LTO. Memfault's Zephyr port
hooks fault handling through linker symbol interposition:

```
ports/zephyr/common/CMakeLists.txt:  zephyr_ld_options(-Wl,--wrap=z_arm_fault)
ports/zephyr/common/CMakeLists.txt:  zephyr_ld_options(-Wl,--wrap=main)
ports/zephyr/panics/CMakeLists.txt:  -Wl,--wrap=z_fatal_error
                                     -Wl,--wrap=arch_new_thread
                                     -Wl,--wrap=z_thread_abort
```

LTO internalises those symbols, so the linker can no longer interpose them:

```
memfault_platform_core.c:65: undefined reference to `z_arm_fault'
zephyr/arch/arm/core/fatal.c:87: undefined reference to `__wrap_z_fatal_error'
```

Coredump capture is the point of the exercise, so `CONFIG_LTO` is off in
`prj_release.conf`. Anyone adding Memfault to an NCS sample that ships an
LTO-enabled release config will hit this.

### The ported modules assumed a shell existed

`nrfcloud_shell.c` is nothing but shell handlers and now drops out of the build
entirely when `CONFIG_SHELL=n`. `jwt.c` needed `#ifdef CONFIG_SHELL` around its
three `cmd_*` functions, because the same file also holds `jwt_generate_psa()`
and `sntp_sync()`, which the telemetry thread needs regardless.

Without those changes a shell-less build fails with
`undefined reference to shell_fprintf_error`. The nRF54L project never
discovered this because it has no shell-less configuration.

## Verified assumptions

Items previously flagged as "verify before relying on this" in
`plans/identity-provisioning.md`, now confirmed against NCS v3.3.0:

| Assumption | Result |
|---|---|
| `MBEDTLS_X509_CSR_WRITE_C` exists as a Kconfig symbol | yes (`nrf_security/Kconfig.tls:59`) |
| `mbedtls_pk_setup_opaque` available | yes — in the linked image |
| `mbedtls_x509write_csr_der` available | yes — in the linked image |
| nRF52840 is a supported Matter platform | yes — `platform_allow` in every Matter sample's `sample.yaml` |
| NAT64 synthesis usable on nRF52840 MTD | yes — `otNat64SynthesizeIp6Address` present |

Still open: persistent PSA key survival across power cycle, and the nRF Cloud
onboarding CSV column order.
