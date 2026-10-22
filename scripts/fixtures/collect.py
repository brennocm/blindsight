"""Discover real Safe transactions on-chain and validate their safeTxHash 3 ways.

Sources per vector:
  A. Safe Transaction Service (official API) -> parameters + safeTxHash
  B. ExecutionSuccess event emitted by the Safe itself (on-chain attestation)
  C. Independent recomputation (safehash.py) using version read on-chain at block-1
A vector is accepted only if A == B == C.
"""
import json, sys, time, urllib.request, urllib.error
sys.path.insert(0, ".")
from safehash import hashes, k

CHAINS = {  # name: (chain_id, drpc host, tx-service short name)
    "ethereum": (1, "eth", "eth"), "arbitrum": (42161, "arbitrum", "arb1"), "base": (8453, "base", "base"),
    "optimism": (10, "optimism", "oeth"), "gnosis": (100, "gnosis", "gno"), "bsc": (56, "bsc", "bnb"),
    "sepolia": (11155111, "sepolia", "sep"), "polygon": (137, "polygon", "pol"),
}
EXEC_SUCCESS = "0x" + k(b"ExecutionSuccess(bytes32,uint256)").hex()


def http(url, body=None, tries=5):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None,
                                         headers={"content-type": "application/json", "user-agent": "research"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500 and e.code != 429:
                return None
            time.sleep(2 * (i + 1))
        except Exception:
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"failed: {url}")


def checksum(a):
    a = a.lower().replace("0x", "")
    h = k(a.encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))


def rpc(chain, method, params):
    url = {"gnosis": "https://rpc.gnosischain.com", "bsc": "https://bsc-dataseed.bnbchain.org"}.get(chain, f"https://{CHAINS[chain][1]}.drpc.org")
    r = http(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if "error" in r:
        raise RuntimeError(r["error"])
    return r["result"]


def api(chain, path):
    time.sleep(0.4)
    return http(f"https://api.safe.global/tx-service/{CHAINS[chain][2]}/api/v1/{path}")


def version_at(chain, safe, block):
    raw = rpc(chain, "eth_call", [{"to": safe, "data": "0xffa1ad74"}, block if isinstance(block, str) else hex(block)])  # VERSION()
    b = bytes.fromhex(raw[2:])
    ln = int.from_bytes(b[32:64], "big")
    return b[64:64 + ln].decode()


def exec_events(receipt, safe=None):
    out = []
    for lg in receipt["logs"]:
        if lg["topics"][0] != EXEC_SUCCESS or (safe and lg["address"].lower() != safe.lower()):
            continue
        h = lg["topics"][1] if len(lg["topics"]) > 1 else "0x" + lg["data"][2:66]
        out.append((lg["address"], h))
    return out


def validate(chain, tx_hash):
    """Return a fixture dict for every ExecutionSuccess in tx_hash that validates 3-way."""
    cid = CHAINS[chain][0]
    rc = rpc(chain, "eth_getTransactionReceipt", [tx_hash])
    tx = rpc(chain, "eth_getTransactionByHash", [tx_hash])
    block = int(rc["blockNumber"], 16)
    res = []
    for safe, h in exec_events(rc):
        a = api(chain, f"multisig-transactions/{h}/")
        if not a:
            print(f"  skip {h}: not in tx service", file=sys.stderr); continue
        try:
            ver = version_at(chain, safe, block - 1); vsrc = f"eth_call VERSION() on {a['safe']} at block {block - 1}"
        except RuntimeError:
            ver = version_at(chain, safe, "latest"); vsrc = f"eth_call VERSION() on {a['safe']} at latest block (no archive RPC); confirmed by recomputed hash == on-chain event"
        d, m, f = hashes(ver, cid, safe, a["to"], int(a["value"]), a["data"] or "0x", a["operation"], int(a["safeTxGas"]),
                         int(a["baseGas"]), int(a["gasPrice"]), a["gasToken"], a["refundReceiver"], int(a["nonce"]))
        ok = (f == h.lower() == a["safeTxHash"].lower())
        print(f"  {chain} v{ver} nonce={a['nonce']} {h} api={a['safeTxHash'] == h} recompute={f == h} method={(a.get('dataDecoded') or {}).get('method')} op={a["operation"]}", file=sys.stderr)
        if not ok:
            continue
        fx = {
            "chain_id": cid, "chain": chain, "safe": a["safe"], "safe_version": ver,
            "tx": {x: a[x] for x in ["to", "value", "data", "operation", "safeTxGas", "baseGas", "gasPrice", "gasToken", "refundReceiver", "nonce"]},
            "expected": {"domain_hash": d, "message_hash": m, "safe_tx_hash": f},
            "decoded_by_tx_service": a.get("dataDecoded"),
            "evidence": {
                "execution_tx_hash": tx_hash, "block_number": block,
                "tx_service_url": f"https://api.safe.global/tx-service/{CHAINS[chain][2]}/api/v1/multisig-transactions/{h}/",
                "execution_success_event_tx_hash": h,
                "version_source": vsrc,
            },
        }
        fx["tx"]["data"] = fx["tx"]["data"] or "0x"
        if tx["to"] and tx["to"].lower() == safe.lower() and tx["input"].startswith("0x6a761202"):
            fx["exec_calldata"] = tx["input"]
        res.append(fx)
    return res


def discover(chain, topic0, span=9000, windows=3, stop_after=200):
    bn = int(rpc(chain, "eth_blockNumber", []), 16)
    found = []
    for w in range(windows):
        hi = bn - w * span
        logs = rpc(chain, "eth_getLogs", [{"fromBlock": hex(hi - span + 1), "toBlock": hex(hi), "topics": [topic0]}])
        found += [(lg["transactionHash"], lg["address"]) for lg in logs]
        if len(found) >= stop_after:
            break
    return found


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "validate":
        print(json.dumps(validate(sys.argv[2], sys.argv[3]), indent=2))
    elif cmd == "discover":
        sig = sys.argv[3].encode()
        for t, a in discover(sys.argv[2], "0x" + k(sig).hex(), windows=int(sys.argv[4]) if len(sys.argv) > 4 else 3):
            print(t, a)
