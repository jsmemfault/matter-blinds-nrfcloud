#
# Smart window covering with Memfault observability over nRF Cloud CoAP.
# nRF52840 — based on the NCS matter/window_covering sample.
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr HINTS $ENV{ZEPHYR_BASE})

project(blinds-nrf52840)

# Enable GNU STD support.
include(${ZEPHYR_CONNECTEDHOMEIP_MODULE_DIR}/config/nrfconnect/app/enable-gnu-std.cmake)

# Include all source files that are located in the Matter common directory.
include(${ZEPHYR_NRF_MODULE_DIR}/samples/matter/common/cmake/source_common.cmake)

# Include Data Model utils
include(${ZEPHYR_NRF_MODULE_DIR}/samples/matter/common/cmake/data_model.cmake)

include(${ZEPHYR_NRF_MODULE_DIR}/samples/matter/common/cmake/zap_helpers.cmake)
ncs_get_zap_parent_dir(ZAP_PARENT_DIR)

# src/ must be a global include so the Memfault SDK can find
# memfault_metrics_heartbeat_config.def and memfault_platform_config.h
zephyr_include_directories(src)

target_include_directories(app PRIVATE
  src
  ${ZAP_PARENT_DIR}
)

# --- Window covering application (from the NCS sample) ---
target_sources(app PRIVATE
  src/main.cpp
  src/app_task.cpp
  src/window_covering.cpp
  src/zcl_callbacks.cpp
)

# --- Observability stack ---
# Ported unchanged from openevse-nrf54l15 apart from blinds.cpp replacing the
# EVSE state source. Everything here is silicon-agnostic: OpenThread native UDP,
# mbedTLS DTLS, PSA crypto, no Zephyr IP stack.
target_sources(app PRIVATE
  src/blinds.cpp
  src/telemetry.c
  src/dtls_transport.c
  src/coap_codec.c
  src/jwt.c
  src/matter_metrics.cpp
)

# nrfcloud_shell.c is nothing but shell command handlers, so it drops out of a
# release image entirely. jwt.c keeps its handlers behind #ifdef CONFIG_SHELL
# because the same file also holds jwt_generate_psa() and sntp_sync(), which
# the telemetry thread needs.
if(CONFIG_SHELL)
  target_sources(app PRIVATE src/nrfcloud_shell.c)
endif()

if(CONFIG_BLINDS_UDP_ECHO_SHELL)
  target_sources(app PRIVATE src/udp_echo_shell.c)
endif()

if(CONFIG_BLINDS_THREAD_AUTOJOIN)
  target_sources(app PRIVATE src/thread_prov.c)
endif()

if(CONFIG_PROVISIONING)
  target_sources(app PRIVATE
    src/provisioning.c
    src/provisioning_attest.cpp
    src/csr.c
  )
endif()

if(CONFIG_PROVISIONING_SHELL)
  target_sources(app PRIVATE src/provisioning_shell.c)
endif()

ncs_configure_data_model()
