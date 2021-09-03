#!/bin/bash
cd "$(dirname "$0")" || exit

# Helper scripts to initialize test wallets
# Usage:
# - Start bitcoind in your system with regtest mode
# - ensure bitcoin-cli is in $PATH
# - create a new wallet: `bitcoin-cli createwallet teleport`
# - run this script: `$ path-to-project-repo/tests/init.sh`
#
# This will set up 1 taker and 2 maker wallet in tests dir.
# If it works you should see the usual wallet balances
# run the taker and makers as usual.

coinbaseaddr=$(bitcoin-cli getnewaddress)

bitcoin-cli generatetoaddress 101 "$coinbaseaddr"


taker='../target/debug/teleport --wallet-file-name taker-wallet'
maker1='../target/debug/teleport --wallet-file-name maker-wallet-1'
maker2='../target/debug/teleport --wallet-file-name maker-wallet-2'


echo -ne "\n" | $taker generate-wallet
echo -ne "\n" | $maker1 generate-wallet
echo -ne "\n" | $maker2 generate-wallet

for number in {0..2}
    do
        takeraddr=$($taker get-receive-invoice)
        bitcoin-cli sendtoaddress $takeraddr 0.05

        maker1addr=$($maker1 get-receive-invoice)
        bitcoin-cli sendtoaddress $maker1addr 0.05

        maker2addr=$($maker2 get-receive-invoice)
        bitcoin-cli sendtoaddress $maker2addr 0.05
    done

bitcoin-cli generatetoaddress 1 "$coinbaseaddr"

echo 'Taker Balance: '
$taker wallet-balance


echo 'Maker1 Balance: '
$maker1 wallet-balance

echo 'Maker2 balance: '
$maker2 wallet-balance