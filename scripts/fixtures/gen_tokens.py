"""Generate data/tokens.json: a short, curated token list, checked on chain.

Source: the Uniswap Labs default token list (npm package
@uniswap/default-token-list, file build/uniswap-default.tokenlist.json).
Second source: each token's own contract, read over public RPC with
symbol() and decimals(). A token is kept only if both agree.

Uses the network (research tooling, not part of blindsight).

Usage: python gen_tokens.py <uniswap-default.tokenlist.json> <package version> > data/tokens.json
"""
import json
import sys

from collect import rpc

SYMBOLS = ["USDC", "USDT", "DAI", "WETH", "WBTC", "LINK"]
CHAINS = {
    1: "ethereum", 10: "optimism", 56: "bsc", 137: "polygon",
    8453: "base", 42161: "arbitrum", 11155111: "sepolia",
}
SYMBOL_SELECTOR = "0x95d89b41"    # symbol()
DECIMALS_SELECTOR = "0x313ce567"  # decimals()


def decode_string(hex_result: str) -> str:
    b = bytes.fromhex(hex_result[2:])
    if len(b) == 32:  # bytes32-style symbol
        return b.rstrip(b"\x00").decode()
    offset = int.from_bytes(b[0:32], "big")
    length = int.from_bytes(b[offset:offset + 32], "big")
    return b[offset + 32: offset + 32 + length].decode()


path, version = sys.argv[1], sys.argv[2]
tokenlist = json.load(open(path))
out = []
for t in tokenlist["tokens"]:
    if t["symbol"] not in SYMBOLS or t["chainId"] not in CHAINS:
        continue
    chain = CHAINS[t["chainId"]]
    call = lambda data: rpc(chain, "eth_call", [{"to": t["address"], "data": data}, "latest"])
    symbol = decode_string(call(SYMBOL_SELECTOR))
    decimals = int(call(DECIMALS_SELECTOR), 16)
    if symbol != t["symbol"] or decimals != t["decimals"]:
        print(f"skip {t['chainId']} {t['address']}: list says {t['symbol']}/{t['decimals']}, "
              f"contract says {symbol}/{decimals}", file=sys.stderr)
        continue
    out.append({
        "chain_id": t["chainId"],
        "address": t["address"],
        "symbol": t["symbol"],
        "name": t["name"],
        "decimals": t["decimals"],
    })

out.sort(key=lambda x: (x["chain_id"], x["symbol"]))
print(json.dumps({
    "source": "npm @uniswap/default-token-list " + version + " (build/uniswap-default.tokenlist.json)",
    "verification": "symbol() and decimals() read from each contract over public RPC; only matching tokens kept",
    "tokens": out,
}, indent=1))
