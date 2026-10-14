#!/usr/bin/env bash
#
# Upload the application symbol file for a build to Memfault.
#
# Memfault serialises heartbeat metrics by their *index* in
# memfault_metrics_heartbeat_config.def, not by name, and recovers the names
# from the symbol file at ingestion. Without a matching upload a build's
# metrics arrive and resolve to nothing, and coredumps have no backtrace. So
# every build that goes on hardware needs its symbols uploaded, and the build
# ID is what pairs the two.
#
# Usage:
#   tools/upload_symbols.sh [build_dir]            # default: build
#   tools/upload_symbols.sh --dry-run [build_dir]  # resolve and print, upload nothing
#
# Credentials come from .memfault.env (gitignored) or the environment.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
	DRY_RUN=1
	shift
fi
BUILD_DIR="${1:-${REPO_ROOT}/build}"

# ---- credentials -----------------------------------------------------------
if [[ -f "${REPO_ROOT}/.memfault.env" ]]; then
	# shellcheck disable=SC1091
	set -a; . "${REPO_ROOT}/.memfault.env"; set +a
fi

missing=()
if (( DRY_RUN )); then
	missing=()
else
[[ -n "${MEMFAULT_ORG_TOKEN:-}" ]] || missing+=(MEMFAULT_ORG_TOKEN)
[[ -n "${MEMFAULT_ORG:-}"       ]] || missing+=(MEMFAULT_ORG)
[[ -n "${MEMFAULT_PROJECT:-}"   ]] || missing+=(MEMFAULT_PROJECT)
if (( ${#missing[@]} )); then
	echo "error: missing ${missing[*]}" >&2
	echo "       copy .memfault.env.example to .memfault.env and fill it in" >&2
	exit 1
fi
fi

# ---- locate the application ELF --------------------------------------------
# A sysbuild tree holds several images (mcuboot, b0n, ipc_radio on the nRF5340).
# Only the application carries the Memfault build ID we care about, so pick the
# image whose .config enables Memfault rather than hardcoding the project name.
app_elf=""
while IFS= read -r cfg; do
	img_dir="$(dirname "${cfg}")"
	if grep -q '^CONFIG_MEMFAULT=y' "${cfg}" && [[ -f "${img_dir}/zephyr.elf" ]]; then
		app_elf="${img_dir}/zephyr.elf"
		break
	fi
done < <(find "${BUILD_DIR}" -mindepth 3 -maxdepth 3 -name .config -path '*/zephyr/*' 2>/dev/null | sort)

if [[ -z "${app_elf}" ]]; then
	echo "error: no Memfault-enabled application ELF under ${BUILD_DIR}" >&2
	exit 1
fi
img_cfg="$(dirname "${app_elf}")/.config"

# ---- build ID and software version -----------------------------------------
readelf_bin="$(command -v arm-zephyr-eabi-readelf || true)"
if [[ -z "${readelf_bin}" ]]; then
	readelf_bin="$(ls /opt/nordic/ncs/toolchains/*/opt/zephyr-sdk/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-readelf 2>/dev/null | head -1 || true)"
fi
[[ -n "${readelf_bin}" ]] || { echo "error: arm-zephyr-eabi-readelf not found" >&2; exit 1; }

build_id="$("${readelf_bin}" -n "${app_elf}" | awk '/Build ID:/ {print $3}')"
[[ -n "${build_id}" ]] || { echo "error: no GNU build ID in ${app_elf}" >&2; exit 1; }

kconf() { sed -n "s/^$1=\"\(.*\)\"$/\1/p" "${img_cfg}"; }
sw_type="$(kconf CONFIG_MEMFAULT_NCS_FW_TYPE)"
prefix="$(kconf CONFIG_MEMFAULT_NCS_FW_VERSION_PREFIX)"

# Mirror memfault_platform_get_device_info(): prefix + first 6 build ID chars.
# Keep this in step with CONFIG_MEMFAULT_NCS_FW_VERSION_AUTO, or the symbols get
# filed under a version no device ever reports.
if [[ -n "${prefix}" ]]; then
	sw_version="${prefix}${build_id:0:6}"
else
	sw_version="$(kconf CONFIG_MEMFAULT_NCS_FW_VERSION)"
fi

cat <<INFO
image:            ${app_elf}
build ID:         ${build_id}
software type:    ${sw_type:-<unset>}
software version: ${sw_version:-<unset>}
project:          ${MEMFAULT_ORG:-<unset>}/${MEMFAULT_PROJECT:-<unset>}
INFO

if (( DRY_RUN )); then
	echo "dry run: nothing uploaded"
	exit 0
fi

args=(--org-token "${MEMFAULT_ORG_TOKEN}" --org "${MEMFAULT_ORG}" --project "${MEMFAULT_PROJECT}"
      upload-mcu-symbols)
# The build ID alone identifies the symbols; passing the version as well makes
# them retrievable by version in the UI, which is what you actually reach for.
[[ -n "${sw_type}"    ]] && args+=(--software-type "${sw_type}")
[[ -n "${sw_version}" ]] && args+=(--software-version "${sw_version}")
args+=("${app_elf}")

exec memfault "${args[@]}"
