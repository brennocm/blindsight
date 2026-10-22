"""Generate data/safe_deployments.json from a checkout of safe-global/safe-deployments.

usage: python gen_deployments.py <path-to-safe-deployments> <commit> > data/safe_deployments.json
"""
import json, glob, os, sys

ROLES = {
    "GnosisSafe": "singleton", "Safe": "singleton", "GnosisSafeL2": "singleton_l2", "SafeL2": "singleton_l2",
    "ProxyFactory": "proxy_factory", "GnosisSafeProxyFactory": "proxy_factory", "SafeProxyFactory": "proxy_factory",
    "MultiSend": "multi_send", "MultiSendCallOnly": "multi_send_call_only", "SignMessageLib": "sign_message_lib",
    "CreateCall": "create_call", "SafeMigration": "migration", "SafeToL2Migration": "migration",
    "SafeToL2Setup": "l2_setup", "CompatibilityFallbackHandler": "fallback_handler",
    "DefaultCallbackHandler": "fallback_handler", "TokenCallbackHandler": "fallback_handler",
    "ExtensibleFallbackHandler": "fallback_handler", "SimulateTxAccessor": "simulate_tx_accessor",
    "CreateAndAddModules": "create_and_add_modules",
}
root, commit = sys.argv[1], sys.argv[2]
contracts = []
for f in sorted(glob.glob(os.path.join(root, "src/assets/v*/*.json"))):
    d = json.load(open(f))
    chains = {}
    for cid, types in d["networkAddresses"].items():
        chains[cid] = sorted(types if isinstance(types, list) else [types])
    contracts.append({
        "name": d["contractName"], "version": d["version"], "role": ROLES[d["contractName"]],
        "released": d.get("released", True),
        "deployments": {k: v["address"] for k, v in sorted(d["deployments"].items())},
        "chains": dict(sorted(chains.items(), key=lambda kv: int(kv[0]))),
        "source_file": os.path.relpath(f, root),
    })
print(json.dumps({"source": "https://github.com/safe-global/safe-deployments", "commit": commit, "contracts": contracts}, indent=1))
