# Provenance and licensing

This project is assembled from three sources. They do not share a licence, and
**one of them is unresolved** — see the blocker at the bottom before publishing.

## 1. Nordic Semiconductor — NCS `samples/matter/window_covering`

The window covering application, board support, partition layout and the
pre-generated ZAP data model are taken from the nRF Connect SDK sample, with
two hooks added (`matter_metrics_init()` in `app_task.cpp`, and
`blinds_record_move_start()` in `window_covering.cpp`).

```
src/main.cpp              src/window_covering.cpp    src/chip_project_config.h
src/app_task.cpp          src/window_covering.h      src/default_zap/**
src/app_task.h            src/zcl_callbacks.cpp      boards/**
pm_static_nrf52840dk_nrf52840.yml                     sysbuild/**
```

Copyright (c) Nordic Semiconductor ASA.
`SPDX-License-Identifier: LicenseRef-Nordic-5-Clause` — headers are intact and
must stay intact. That licence permits redistribution in binary and source form
for use with Nordic devices; read it before relicensing anything above.

## 2. Original work in this project

Copyright (c) 2026 Jon Sharp. `SPDX-License-Identifier: Apache-2.0`.

```
src/blinds.cpp / .h                 observability view of the covering
src/matter_metrics.cpp / .h         Thread + Matter diagnostics collection
src/provisioning.c / .h             on-die keygen, CSR, certificate storage
src/provisioning_attest.cpp         Matter DAC attestation of the CSR
src/provisioning_shell.c            factory fixture commands
tools/provision.py                  factory driver
src/memfault_metrics_heartbeat_config.def
plans/**
```

## 3. `memfault/ncs-example-matter-over-thread` — UNRESOLVED

The Memfault-over-nRF-Cloud-CoAP transport originates in
<https://github.com/memfault/ncs-example-matter-over-thread> by
François Baldassari, extended in this project.

```
src/dtls_transport.c / .h     src/jwt.c / .h          src/telemetry.c
src/coap_codec.c / .h         src/nrfcloud_shell.c    src/udp_echo_shell.c
src/thread_prov.c / .h        src/memfault_platform_config.h
```

**That repository carries no LICENSE file and these files carry no copyright
headers.** Absent a licence grant, the default position is all rights reserved,
which means this project cannot be published under Apache-2.0 — or any licence —
while it contains them.

Resolving it needs one of:

- a licence added upstream (Apache-2.0 or MIT would match the intent of an
  example repository), after which these files inherit it and get headers here;
- written permission from the copyright holder to redistribute under a named
  licence; or
- the files removed from this repository and consumed as an external dependency
  from upstream instead.

Until one of those happens, treat this repository as **private**. Everything in
sections 1 and 2 is clear; section 3 is the only thing in the way.
