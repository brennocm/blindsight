"""Generate tests/fixtures/synthetic/hashing-edge-cases.json.

Edge cases no real transaction covers (empty and large calldata, maximum
values, zero addresses, extreme chain ids). Expected hashes come from
safehash.py, the reference written from the contract sources; the Rust tests
then check both Rust implementations against them. No network.

Usage: python gen_synthetic.py > ../../tests/fixtures/synthetic/hashing-edge-cases.json
"""
import json

from safehash import hashes

MAX = 2**256 - 1
ZERO = "0x" + "00" * 20
SAFE = "0x" + "5a" * 20
ADDR = "0x" + "c0ffee" + "00" * 15 + "beef"


def case(name, version, chain_id, safe=SAFE, to=ADDR, value=0, data="0x", operation=0,
         safe_tx_gas=0, base_gas=0, gas_price=0, gas_token=ZERO, refund_receiver=ZERO, nonce=0):
    d, m, f = hashes(version, chain_id, safe, to, value, data, operation, safe_tx_gas,
                     base_gas, gas_price, gas_token, refund_receiver, nonce)
    return {
        "name": name,
        "chain_id": chain_id,
        "safe": safe,
        "safe_version": version,
        "tx": {
            "to": to, "value": str(value), "data": data, "operation": operation,
            "safeTxGas": str(safe_tx_gas), "baseGas": str(base_gas), "gasPrice": str(gas_price),
            "gasToken": gas_token, "refundReceiver": refund_receiver, "nonce": str(nonce),
        },
        "expected": {"domain_hash": d, "message_hash": m, "safe_tx_hash": f},
    }


cases = []
for v in ["1.0.0", "1.1.1", "1.2.0", "1.3.0", "1.4.1", "1.5.0"]:
    tag = v.replace(".", "")
    cases += [
        case(f"empty-data-{tag}", v, 1),
        case(f"all-zero-{tag}", v, 1, safe=ZERO, to=ZERO),
        case(f"all-max-{tag}", v, 2**64 - 1, value=MAX, operation=1, safe_tx_gas=MAX,
             base_gas=MAX, gas_price=MAX, gas_token="0x" + "ff" * 20,
             refund_receiver="0x" + "ff" * 20, nonce=MAX),
    ]
cases += [
    # One byte, one word plus one, and 16 KiB of calldata.
    case("data-1-byte", "1.4.1", 1, data="0x00"),
    case("data-33-bytes", "1.4.1", 1, data="0x" + "11" * 33),
    case("data-16kib", "1.4.1", 137, data="0x" + bytes(range(256)).hex() * 64),
    # Same transaction, same Safe, different chains: identical before 1.3.0.
    case("replay-111-chain-1", "1.1.1", 1, nonce=5),
    case("replay-111-chain-100", "1.1.1", 100, nonce=5),
    case("chain-id-0-130", "1.3.0", 0),
]
print(json.dumps(cases, indent=1))
