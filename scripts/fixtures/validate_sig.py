"""3-way validation for Safes without ExecutionSuccess (v1.0.0):
A = tx-service safeTxHash, B = on-chain signatures recover to owners (getOwners at block-1) over our hash,
C = recomputation from the on-chain execTransaction calldata."""
import sys, json
sys.path.insert(0, ".")
from collect import rpc, api, version_at, CHAINS, checksum
from safehash import hashes, decode_exec
from ecrecover import safe_signers
chain, txh = sys.argv[1], sys.argv[2]
tx = rpc(chain, "eth_getTransactionByHash", [txh]); rc = rpc(chain, "eth_getTransactionReceipt", [txh])
safe = checksum(tx["to"]); block = int(rc["blockNumber"], 16)
assert rc["status"] == "0x1" and tx["input"].startswith("0x6a761202")
p = decode_exec(tx["input"])
ver = version_at(chain, safe, block - 1)
nonce = int(rpc(chain, "eth_call", [{"to": safe, "data": "0xaffed0e0"}, hex(block - 1)]), 16)
owners_raw = bytes.fromhex(rpc(chain, "eth_call", [{"to": safe, "data": "0xa0e67e2b"}, hex(block - 1)])[2:])
n = int.from_bytes(owners_raw[32:64], "big")
owners = {"0x" + owners_raw[64 + 32 * i + 12: 96 + 32 * i].hex() for i in range(n)}
thr = int(rpc(chain, "eth_call", [{"to": safe, "data": "0xe75235b8"}, hex(block - 1)]), 16)
d, m, f = hashes(ver, CHAINS[chain][0], safe, p["to"], int(p["value"]), p["data"], p["operation"], int(p["safeTxGas"]),
                 int(p["baseGas"]), int(p["gasPrice"]), p["gasToken"], p["refundReceiver"], nonce)
signers = safe_signers(f, p["signatures"])
recovered_owners = [a for kind, a in signers if kind in ("eoa", "eth_sign") and a in owners]
a = api(chain, f"multisig-transactions/{f}/")
ok_api = bool(a) and a["safeTxHash"].lower() == f
ok_sig = len(recovered_owners) >= thr
print(f"  {chain} v{ver} nonce={nonce} {f} api={ok_api} sigs={len(recovered_owners)}/{thr} kinds={[s[0] for s in signers]}", file=sys.stderr)
if ok_api and ok_sig:
    print(json.dumps([{
        "chain_id": CHAINS[chain][0], "chain": chain, "safe": safe, "safe_version": ver,
        "tx": {"to": checksum(p["to"]), "value": p["value"], "data": p["data"], "operation": p["operation"], "safeTxGas": int(p["safeTxGas"]),
               "baseGas": int(p["baseGas"]), "gasPrice": p["gasPrice"], "gasToken": checksum(p["gasToken"]), "refundReceiver": checksum(p["refundReceiver"]), "nonce": nonce},
        "expected": {"domain_hash": d, "message_hash": m, "safe_tx_hash": f},
        "decoded_by_tx_service": a.get("dataDecoded"),
        "exec_calldata": tx["input"],
        "evidence": {"execution_tx_hash": txh, "block_number": block,
                     "tx_service_url": f"https://api.safe.global/tx-service/{CHAINS[chain][2]}/api/v1/multisig-transactions/{f}/",
                     "signature_recovery": f"{len(recovered_owners)} of threshold {thr} signatures recover to owners (getOwners() at block {block - 1})",
                     "recovered_signers": recovered_owners,
                     "version_source": f"eth_call VERSION() on {safe} at block {block - 1}"}}], indent=2))
