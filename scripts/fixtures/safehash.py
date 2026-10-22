"""Independent reference implementation of Safe EIP-712 hashing (research only).

Written from the Safe contract sources, not from any existing tool, so it can
serve as a cross-check against the official Transaction Service and on-chain
ExecutionSuccess events while collecting test vectors.
"""
from Crypto.Hash import keccak


def k(b: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=b).digest()


DOMAIN_NO_CHAIN = k(b"EIP712Domain(address verifyingContract)")
DOMAIN_CHAIN = k(b"EIP712Domain(uint256 chainId,address verifyingContract)")
SAFE_TX_BASEGAS = k(b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
SAFE_TX_DATAGAS = k(b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 dataGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")


def vparse(v: str):
    return tuple(int(x) for x in v.split("+")[0].split("-")[0].split("."))


def word_int(n: int) -> bytes:
    return int(n).to_bytes(32, "big")


def word_addr(a: str) -> bytes:
    b = bytes.fromhex(a[2:] if a.startswith("0x") else a)
    assert len(b) == 20
    return b"\x00" * 12 + b


def hashes(version, chain_id, safe, to, value, data, operation, safe_tx_gas, base_gas, gas_price, gas_token, refund_receiver, nonce):
    v = vparse(version)
    if v >= (1, 3, 0):
        domain = k(DOMAIN_CHAIN + word_int(chain_id) + word_addr(safe))
    else:
        domain = k(DOMAIN_NO_CHAIN + word_addr(safe))
    typehash = SAFE_TX_BASEGAS if v >= (1, 0, 0) else SAFE_TX_DATAGAS
    data_b = bytes.fromhex(data[2:] if data and data.startswith("0x") else (data or ""))
    msg = k(typehash + word_addr(to) + word_int(value) + k(data_b) + word_int(operation)
            + word_int(safe_tx_gas) + word_int(base_gas) + word_int(gas_price)
            + word_addr(gas_token) + word_addr(refund_receiver) + word_int(nonce))
    final = k(b"\x19\x01" + domain + msg)
    return "0x" + domain.hex(), "0x" + msg.hex(), "0x" + final.hex()


def decode_exec(calldata: str) -> dict:
    """Decode execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)."""
    b = bytes.fromhex(calldata[2:])
    assert b[:4].hex() == "6a761202", "not execTransaction"
    a = b[4:]
    w = lambda i: a[32 * i: 32 * i + 32]
    to_int = lambda x: int.from_bytes(x, "big")
    addr = lambda x: "0x" + x[12:].hex()

    def dyn(off):
        ln = to_int(a[off: off + 32])
        return "0x" + a[off + 32: off + 32 + ln].hex()

    return {
        "to": addr(w(0)), "value": str(to_int(w(1))), "data": dyn(to_int(w(2))),
        "operation": to_int(w(3)), "safeTxGas": str(to_int(w(4))), "baseGas": str(to_int(w(5))),
        "gasPrice": str(to_int(w(6))), "gasToken": addr(w(7)), "refundReceiver": addr(w(8)),
        "signatures": dyn(to_int(w(9))),
    }
