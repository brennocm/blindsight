"""Generate data/chains.json from a checkout of ethereum-lists/chains.

Keeps only the chains where data/safe_deployments.json lists at least one
official Safe deployment, with their name and native currency. No network:
point it at a local checkout.

Usage: python gen_chains.py <ethereum-lists/chains checkout> <commit> > data/chains.json
"""
import json
import os
import sys

src, commit = sys.argv[1], sys.argv[2]
here = os.path.dirname(os.path.abspath(__file__))
deployments = json.load(open(os.path.join(here, "../../data/safe_deployments.json")))
wanted = set()
for contract in deployments["contracts"]:
    wanted.update(int(c) for c in contract["chains"])

chains = []
missing = []
for chain_id in sorted(wanted):
    path = os.path.join(src, "_data/chains", f"eip155-{chain_id}.json")
    if not os.path.exists(path):
        missing.append(chain_id)
        continue
    d = json.load(open(path))
    assert d["chainId"] == chain_id, path
    name = d["name"]
    symbol = d["nativeCurrency"]["symbol"]
    # Keep the embedded data plain: printable ASCII only.
    assert name.isascii() and name.isprintable(), (chain_id, name)
    assert symbol.isascii() and symbol.isprintable(), (chain_id, symbol)
    chains.append({
        "chain_id": chain_id,
        "name": name,
        "native_symbol": symbol,
        "native_decimals": d["nativeCurrency"]["decimals"],
    })

print(json.dumps({
    "source": "https://github.com/ethereum-lists/chains",
    "commit": commit,
    "note": "Chains with at least one official Safe deployment in safe_deployments.json.",
    "missing_from_source": missing,
    "chains": chains,
}, indent=1))
