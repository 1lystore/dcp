#!/usr/bin/env python3
"""
DCP Local Agent Test - No external dependencies
"""

import urllib.request
import urllib.error
import json
import sys


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())
    except urllib.error.URLError as e:
        return {"error": {"code": "CONNECTION_FAILED", "message": str(e.reason)}}


def post(url, data):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())
    except urllib.error.URLError as e:
        return {"error": {"code": "CONNECTION_FAILED", "message": str(e.reason)}}


def main():
    proxy = "http://127.0.0.1:8420"

    print("=" * 60)
    print("DCP Local Agent Test")
    print("=" * 60)
    print(f"\nProxy: {proxy}\n")

    # 1. Health
    print("[1] Health Check")
    print("-" * 40)
    h = get(f"{proxy}/health")
    if "error" in h:
        print(f"  ERROR: {h['error']['message']}")
        print("  Is dcp-agent running?")
        return 1
    print(f"  Status: {h.get('status')}")
    print(f"  Agent: {h.get('agent_name')} ({h.get('agent_id')})")
    print(f"  Vault: {h.get('vault_id')}")
    print(f"  Connected: {h.get('connected')}")
    print()

    # 2. Capabilities
    print("[2] Capabilities")
    print("-" * 40)
    c = get(f"{proxy}/capabilities")
    print(f"  Scopes: {c.get('permission_scopes')}")
    print(f"  Tier: {c.get('tier')}")
    print()

    # 3. Get address
    print("[3] Get Solana Address")
    print("-" * 40)
    a = get(f"{proxy}/address/solana")
    if "error" in a:
        print(f"  ERROR: {a['error']['code']} - {a['error']['message']}")
        if a['error']['code'] == "CONSENT_REQUIRED":
            print("  -> Check Desktop/Telegram!")
    else:
        print(f"  Address: {a.get('address')}")
    print()

    # 4. Budget check
    print("[4] Budget Check")
    print("-" * 40)
    b = get(f"{proxy}/budget/check?amount=1&currency=USDC")
    if "error" in b:
        print(f"  ERROR: {b['error']['code']}")
    else:
        print(f"  Allowed: {b.get('allowed')}")
        print(f"  Remaining: {b.get('remaining_daily')}")
    print()

    # 5. Read identity
    print("[5] Read identity.email")
    print("-" * 40)
    r = post(f"{proxy}/v1/vault/read", {"scope": "identity.email"})
    if "error" in r:
        err = r['error']
        print(f"  ERROR: {err['code']} - {err.get('message', '')}")
        if err['code'] == "CONSENT_REQUIRED":
            print("  -> Check Desktop/Telegram to approve!")
        elif err['code'] == "RECORD_NOT_FOUND":
            print("  -> No data at this scope (OK for test)")
    else:
        print(f"  Data: {r.get('data')}")
    print()

    print("=" * 60)
    print("DONE")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
