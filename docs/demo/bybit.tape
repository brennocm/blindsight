# Records docs/demo/bybit.gif: blindsight on the Bybit attack transaction.
# Regenerate with: cargo build --release && vhs docs/demo/bybit.tape
Output docs/demo/bybit.gif

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 820
Set Padding 16
Set TypingSpeed 35ms
Set Theme "Builtin Dark"

Hide
Type "export PATH=$PWD/target/release:$PATH && cd docs/demo && clear"
Enter
Show

Type "# The Bybit attack transaction (21 Feb 2025), as the signers' wallets received it"
Enter
Sleep 600ms
Type "blindsight verify --color always --tx bybit-tx.json --chain-id 1 --safe-version 1.1.1 \"
Enter
Type "  --expect-safe-tx-hash 0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8 | head -36"
Sleep 400ms
Enter
Sleep 9s
