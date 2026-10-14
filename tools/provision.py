#!/usr/bin/env python3
# Copyright (c) 2026 Jon Sharp
#
# SPDX-License-Identifier: Apache-2.0

"""
Factory provisioning driver — on-die key generation with DAC-attested CSR.

Runs as extra steps in the fixture pass that already programs firmware and
Matter factory data. No internet is required at the line: the product CA is a
local key or PKCS#11 HSM handle, and nRF Cloud onboarding happens later from
the accumulated CSV.

    device                          this script
    ------                          -----------
    provision keygen         <--    generate key on-die (non-exportable)
    provision bundle         <--    request CSR + attestation
    CSR/DAC/PAI/signature     -->   verify DAC chain, verify attestation
                                    sign CSR with product CA
    provision cert_*         <--    (optional) store issued certificate
                                    append row to onboarding CSV

Usage:
    ./provision.py --port /dev/ttyACM0 --ca ca.pem --ca-key ca-key.pem \\
        --device-id shade-000123 --org Acme --csv onboard.csv

    # Verify only, no CA needed — useful when bringing a line up:
    ./provision.py --port /dev/ttyACM0 --device-id shade-000123 --dry-run

Requires: pyserial, cryptography
"""

import argparse
import base64
import csv
import datetime
import os
import re
import sys

try:
    import serial
except ImportError:
    sys.exit("pyserial required: pip install pyserial")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit("cryptography required: pip install cryptography")


PROMPT = "uart:~$"
B64_LINE = 64

# The Zephyr shell decorates output with cursor-control sequences.
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|[\x00-\x08\x0b-\x1f]")


class ProvisionError(Exception):
    pass


# --------------------------------------------------------------------------
# Device I/O
# --------------------------------------------------------------------------

class Device:
    def __init__(self, port, baud=115200, timeout=10):
        # Small read timeout so idle detection is responsive; `timeout` stays the
        # per-command hard deadline. A 10 s read timeout makes every command that
        # produces no output (cert_data, for one) block for the full 10 s, which
        # turns a nine-chunk certificate upload into minutes.
        self.ser = serial.Serial(port, baud, timeout=0.2)
        self.timeout = timeout

    def close(self):
        self.ser.close()

    def command(self, cmd, idle=0.6):
        """Send a shell command, return its output lines (echo/prompt stripped).

        Reads until the link goes idle rather than scanning for the prompt as a
        whole line: the Zephyr shell emits its prompt with ANSI cursor controls
        and no trailing newline, so it never arrives as one.
        """
        self.ser.reset_input_buffer()
        self.ser.write((cmd + "\r\n").encode())
        self.ser.flush()

        buf = ""
        hard_deadline = datetime.datetime.now() + datetime.timedelta(seconds=self.timeout)
        last_rx = datetime.datetime.now()

        while datetime.datetime.now() < hard_deadline:
            chunk = self.ser.read(4096).decode(errors="replace")
            if chunk:
                buf += chunk
                last_rx = datetime.datetime.now()
            elif buf and (datetime.datetime.now() - last_rx).total_seconds() >= idle:
                break

        if not buf:
            raise ProvisionError(f"no response to: {cmd}")

        text = ANSI_RE.sub("", buf)
        return [
            line.rstrip()
            for line in text.split("\n")
            if line.strip() and PROMPT not in line and line.strip() != cmd
        ]

    def expect_ok(self, cmd):
        out = self.command(cmd)
        joined = " ".join(out)
        if "OK" not in joined and "already exists" not in joined:
            raise ProvisionError(f"'{cmd}' failed: {joined}")
        return out


def parse_blocks(lines):
    """Extract -----BEGIN X----- / -----END X----- base64 blocks."""
    blocks, label, acc = {}, None, []

    for line in lines:
        begin = re.match(r"-+BEGIN ([A-Z ]+)-+$", line)
        end = re.match(r"-+END ([A-Z ]+)-+$", line)
        if begin:
            label, acc = begin.group(1), []
        elif end and label:
            blocks[label] = base64.b64decode("".join(acc))
            label = None
        elif label:
            acc.append(line.strip())

    return blocks


# --------------------------------------------------------------------------
# Attestation verification
# --------------------------------------------------------------------------

def _raw_sig_to_der(raw):
    """Matter emits raw r||s; OpenSSL/cryptography want ASN.1 DER."""
    if len(raw) != 64:
        raise ProvisionError(f"expected 64-byte raw signature, got {len(raw)}")
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    return asym_utils.encode_dss_signature(r, s)


def verify_attestation(csr_der, sig_raw, dac_der, pai_der, paa_dir=None):
    """
    Confirm the CSR came from a genuine device.

    1. The CSR is internally consistent (self-signature valid).
    2. The DAC signed this exact CSR.
    3. The DAC chains to the PAI.
    4. Optionally, the PAI chains to a trusted PAA.

    Step 4 is what ties the device back to a root published on the Matter
    Distributed Compliance Ledger. Skipping it (no --paa-dir) still proves the
    request came from something holding a DAC private key for this PAI, which
    is sufficient on a controlled production line.
    """
    csr = x509.load_der_x509_csr(csr_der)
    if not csr.is_signature_valid:
        raise ProvisionError("CSR self-signature is invalid")

    dac = x509.load_der_x509_certificate(dac_der)
    pai = x509.load_der_x509_certificate(pai_der)

    # 2. DAC signed the CSR
    try:
        dac.public_key().verify(
            _raw_sig_to_der(sig_raw), csr_der, ec.ECDSA(hashes.SHA256())
        )
    except Exception as exc:
        raise ProvisionError(f"DAC attestation signature invalid: {exc}")

    # 3. DAC -> PAI
    try:
        pai.public_key().verify(
            dac.signature,
            dac.tbs_certificate_bytes,
            ec.ECDSA(dac.signature_hash_algorithm),
        )
    except Exception as exc:
        raise ProvisionError(f"DAC does not chain to PAI: {exc}")

    # 4. PAI -> PAA
    if paa_dir:
        for name in os.listdir(paa_dir):
            path = os.path.join(paa_dir, name)
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
                paa = (
                    x509.load_pem_x509_certificate(data)
                    if b"-----BEGIN" in data
                    else x509.load_der_x509_certificate(data)
                )
                paa.public_key().verify(
                    pai.signature,
                    pai.tbs_certificate_bytes,
                    ec.ECDSA(pai.signature_hash_algorithm),
                )
                return csr, dac, paa.subject.rfc4514_string()
            except Exception:
                continue
        raise ProvisionError(f"PAI does not chain to any PAA in {paa_dir}")

    return csr, dac, None


# --------------------------------------------------------------------------
# Certificate issuance
# --------------------------------------------------------------------------

def issue_certificate(csr, ca_cert_path, ca_key_path, days):
    with open(ca_cert_path, "rb") as fh:
        ca_cert = x509.load_pem_x509_certificate(fh.read())
    with open(ca_key_path, "rb") as fh:
        ca_key = serialization.load_pem_private_key(fh.read(), password=None)

    now = datetime.datetime.now(datetime.timezone.utc)

    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )


def upload_certificate(dev, cert_der):
    b64 = base64.b64encode(cert_der).decode()

    dev.expect_ok("provision cert_begin")
    for i in range(0, len(b64), B64_LINE):
        chunk = b64[i : i + B64_LINE]
        out = dev.command(f"provision cert_data {chunk}")
        if any("error" in line.lower() or "failed" in line.lower() for line in out):
            raise ProvisionError(f"cert_data rejected: {out}")
    dev.expect_ok("provision cert_commit")


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="serial port of the device")
    ap.add_argument("--device-id", required=True, help="canonical device ID (CSR CN)")
    ap.add_argument("--org", help="organisation for the CSR subject (O=)")
    ap.add_argument("--ca", help="product CA certificate (PEM)")
    ap.add_argument("--ca-key", help="product CA private key (PEM)")
    ap.add_argument("--paa-dir", help="directory of trusted PAA roots from the DCL")
    ap.add_argument("--csv", help="append an nRF Cloud onboarding row here")
    ap.add_argument("--out-dir", default=".", help="where to write the issued cert")
    ap.add_argument("--days", type=int, default=3650, help="certificate lifetime")
    ap.add_argument("--store-cert", action="store_true",
                    help="write the certificate back to the device (optional — "
                         "nRF Cloud CoAP authenticates by JWT, not client cert)")
    ap.add_argument("--force-keygen", action="store_true",
                    help="replace an existing device key")
    ap.add_argument("--dry-run", action="store_true",
                    help="verify attestation only, do not issue a certificate")
    args = ap.parse_args()

    if not args.dry_run and not (args.ca and args.ca_key):
        ap.error("--ca and --ca-key are required unless --dry-run")

    subject = f"CN={args.device_id}"
    if args.org:
        subject += f",O={args.org}"

    dev = Device(args.port)
    try:
        print(f"[1/5] generating on-die key ({args.device_id})")
        dev.expect_ok("provision keygen" + (" force" if args.force_keygen else ""))

        print("[2/5] requesting attested CSR")
        blocks = parse_blocks(dev.command(f"provision bundle {subject}"))

        required = {"CERTIFICATE REQUEST", "ATTESTATION SIGNATURE", "DAC", "PAI"}
        missing = required - blocks.keys()
        if missing:
            raise ProvisionError(f"device did not emit: {', '.join(sorted(missing))}")

        print("[3/5] verifying DAC attestation")
        csr, dac, paa_name = verify_attestation(
            blocks["CERTIFICATE REQUEST"],
            blocks["ATTESTATION SIGNATURE"],
            blocks["DAC"],
            blocks["PAI"],
            args.paa_dir,
        )

        dac_cn = dac.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        print(f"      DAC subject: {dac_cn[0].value if dac_cn else '(none)'}")
        print(f"      PAA:         {paa_name or '(not checked — no --paa-dir)'}")
        print(f"      CSR subject: {csr.subject.rfc4514_string()}")

        if args.dry_run:
            print("[4/5] dry run — attestation valid, no certificate issued")
            return 0

        print("[4/5] issuing certificate")
        cert = issue_certificate(csr, args.ca, args.ca_key, args.days)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        os.makedirs(args.out_dir, exist_ok=True)
        cert_path = os.path.join(args.out_dir, f"{args.device_id}.pem")
        with open(cert_path, "w") as fh:
            fh.write(cert_pem)
        print(f"      wrote {cert_path} (expires {cert.not_valid_after_utc:%Y-%m-%d})")

        if args.store_cert:
            print("[5/5] storing certificate on device")
            upload_certificate(dev, cert.public_bytes(serialization.Encoding.DER))
        else:
            print("[5/5] skipping device write (--store-cert to enable)")

        if args.csv:
            # Column order follows nRF Cloud's onboarding CSV. Confirm against
            # the version of nrf_cloud_onboard you are running before a real run.
            # No header row: nrf_cloud_onboard POSTs this file verbatim and
            # treats every row as a device, so a header would be onboarded as a
            # device literally named "deviceId".
            # Columns: deviceId, subType, tags, fwTypes, certPem
            with open(args.csv, "a", newline="") as fh:
                w = csv.writer(fh)
                w.writerow([args.device_id, "", "", "", cert_pem])
            print(f"      appended onboarding row to {args.csv}")

        print(f"\nOK: {args.device_id} provisioned")
        return 0

    except ProvisionError as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        dev.close()


if __name__ == "__main__":
    sys.exit(main())
