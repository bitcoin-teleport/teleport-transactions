# Teleport Transactions

Teleport Transactions is software aiming to improve the [privacy](https://en.bitcoin.it/wiki/Privacy) of [bitcoin](https://en.bitcoin.it/wiki/Main_Page).

Suppose Alice has bitcoins and wants to send them with maximal privacy, so she creates a special kind of transaction. For anyone looking at the blockchain her transaction appears completely normal with her coins seemingly going from bitcoin address A to address B. But in reality her coins end up in address Z which is entirely unconnected to either A or B.

Now imagine another user, Carol, who isn't too bothered by privacy and sends her bitcoin using a regular wallet. But because Carol's transaction looks exactly the same as Alice's, anybody analyzing the blockchain must now deal with the possibility that Carol's transaction actually sent her coins to a totally unconnected address. So Carol's privacy is improved even though she didn't change her behaviour, and perhaps had never even heard of this software.

In a world where advertisers, social media and other institutions want to collect all of Alice's and Carol's data, such privacy improvement is incredibly valuable. And the doubt added to every transaction would greatly boost the [fungibility of bitcoin](https://en.bitcoin.it/wiki/Fungibility) and so make it a better form of money.


## Contents

- [State of the project](#state-of-the-project)
- [How to create a CoinSwap on regtest or testnet](#how-to-create-a-coinswap-on-regtest-or-testnet)
- [Developer resources](#developer-resources)
- [Protocol between takers and makers](#protocol-between-takers-and-makers)
- [Notes on architecture](#notes-on-architecture)
- [Chris Belcher's personal roadmap for the project](#chris-belchers-personal-roadmap-for-the-project)
- [Community](#community)

## State of the project

The project is nowhere near usable. The code written so far is published for developers to play around with. It doesn't have config files yet so you have to edit the source files to configure stuff.

## How to create a CoinSwap on regtest or testnet

* Install [rust](https://www.rust-lang.org/) on your machine.

* Start up Bitcoin Core in regtest mode. Make sure the RPC server is enabled with `server=1` and that rpc username and password are set with `rpcuser=yourrpcusername` and `rpcpassword=yourrpcpassword` in the configuration file.

* Download this git repository. Open the file `src/main.rs` and edit the RPC username and password in the function `get_bitcoin_rpc`. Make sure your Bitcoin Core has a wallet called `teleport`, or edit the name in the same function.

* Create two teleport wallets by running `cargo run generate-wallet` twice. Call them something like `maker.teleport` and `taker.teleport`.

* Use `cargo run get-receive-invoice maker.teleport` to obtain 3 addresses of the maker wallet, and send regtest bitcoins to each of them (amount 5000000 satoshi or 0.05 BTC in this example). Do this as well for the `taker.teleport` wallet. Get the transactions confirmed.

* Check your balance with `cargo run wallet-balance maker.teleport`. Example:

```
$ cargo run wallet-balance taker.teleport
outpoint         address                  swapcoin conf    value
8f6ee5..74e813:0 bcrt1q0vn5....nrjdqljtaq    no    1       0.05000000 BTC
d548a8..cadd5e:0 bcrt1qaylc....vnw4ay98jq    no    1       0.05000000 BTC
604ca6..4ab5f0:1 bcrt1qt3jy....df6pmewmzs    no    1       0.05000000 BTC
coin count = 3
total balance = 0.15000000 BTC

```

```
$ cargo run wallet-balance maker.teleport
outpoint         address                  swapcoin conf    value
5f4331..d53f14:0 bcrt1qmflt....q2ucgf2teu    no    1       0.05000000 BTC
6252ee..d827b0:0 bcrt1qu9mk....pwpedjyl9u    no    1       0.05000000 BTC
ac88da..e3ead6:0 bcrt1q3xdx....e7gxtcgrfg    no    1       0.05000000 BTC
coin count = 3
total balance = 0.15000000 BTC
```

* On one terminal run the maker server with `cargo run run-maker maker.teleport`. You should see the message `listening on port 6102`.

* On another terminal start a coinswap with `cargo run coinswap-send taker.teleport`. When you see the terminal messages `waiting for funding transaction to confirm` and `waiting for maker's funding transaction to confirm` then tell regtest to generate another block (or just wait if you're using testnet).

* Once you see the message `successfully completed coinswap` on both terminals then check the wallet balance again to see the result of the coinswap. Example:

```
$ cargo run wallet-balance taker.teleport
outpoint         address                  swapcoin conf    value
d33f06..30dd07:0 bcrt1q8hjk....9g9q444076   yes    1       0.01240012 BTC
8aaa89..ef5613:0 bcrt1qaapk....7ytxhclfm5    no    2       0.04913714 BTC
383ffe..127065:1 bcrt1qrfp3....2n6n57y3cc    no    2       0.02608261 BTC
41789c..93ec7f:1 bcrt1qknhq....fwyqq5gfu0   yes    1       0.03636660 BTC
73271a..7d09b8:1 bcrt1qsxlt....gu3qtpgws5   yes    1       0.00113328 BTC
111a96..1c84dc:0 bcrt1q64hp....ectyys5jvs    no    2       0.02472883 BTC
coin count = 6
total balance = 0.14984858 BTC
```

```
$ cargo run wallet-balance maker.teleport
outpoint         address                  swapcoin conf    value
d33f06..30dd07:1 bcrt1q6dqq....hyv7ak568q    no    1       0.03758274 BTC
8aaa89..ef5613:1 bcrt1qw74e....9phqzpvflr   yes    2       0.00084572 BTC
383ffe..127065:0 bcrt1qrtug....hgss04vpqn   yes    2       0.02390025 BTC
41789c..93ec7f:0 bcrt1qta5h....htq77mazlu    no    1       0.01361626 BTC
73271a..7d09b8:0 bcrt1qd9x6....xnldz7xhu7    no    1       0.04884958 BTC
111a96..1c84dc:1 bcrt1qe70f....3rusg3whuf   yes    2       0.02525403 BTC
coin count = 6
total balance = 0.15004858 BTC
```

* To switch between regtest and testnet, edit the constant `NETWORK` which is found near the top of the file `src/wallet_sync.rs`. To edit the coinswap send amount, or the number of taker and maker transactions, look in the file `src/taker_protocol.rs` near the top of the function `send_coinswap`.


## Developer resources

Here are links to some reading material for any developers who want to get up to speed.

* [Design for a CoinSwap Implementation for Massively Improving Bitcoin Privacy and Fungibility](https://gist.github.com/chris-belcher/9144bd57a91c194e332fb5ca371d0964) - High level design explaining all the building blocks

* [gmaxwell's original coinswap writeup from 2013](https://bitcointalk.org/index.php?topic=321228.0). It explains how CoinSwap actually works. If you already understand how Lightning payment channels work then CoinSwap is similar.

* [Design for improving JoinMarket's resistance to sybil attacks using fidelity bonds](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af/). Document explaining the concept of fidelity bonds and how they provide resistance against sybil attacks.


### Protocol between takers and makers

Alice is the taker, Bob and Charlie are makers. For a detailed explanation including definitions see the mailing list email [here](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-October/018221.html). That email should be read first and then you can jump back to the diagram below when needed while reading the code.

Protocol messages are defined by the structs found in `src/messages.rs` and serialized into json with rust's serde crate.

```
 | Alice           | Bob             | Charlie         | message name, or (step) if its a repeat
 |=================|=================|=================|
0. AB/A htlc + p ---->               |                 | sign my senders contract
1.               <---- AB/A htlc B/2 |                 | your senders contract sig
2.    ***** BROADCAST AND MINE ALICE FUNDING TX *****  |
3.    A fund + p ---->               |                 | proof of funding
4.               <----AB/B+BC/B htlc |                 | sign my senders and receivers contract
5. BC/B htlc + p ---------------------->               | (0)
6.               <---------------------- BC/B htlc C/2 | (1)
7. AB/B+BC/B A+C/2--->               |                 | your senders and receivers contract
8.    ***** BROADCAST AND MINE BOB FUNDING TX *****    |
A.    B fund + p ----------------------->              | (3)
B.               <-----------------------BC/C+CA/C htlc| (4)
C. BC/C htlc + p ---->               |                 | sign my receiver contract
D.               <---- BC/C htlc B/2 |                 | your receiver contract
E.BC/C+CA/C B+A/2----------------------->              | (7)
E.   ***** BROADCAST AND MINE CHARLIE FUNDING TX ***** |
G. CA/A htlc + p ---------------------->               | (C)
H.               <---------------------- CA/A htlc C/2 | (D)
I. hash preimage ---------------------->               | hash preimage
J. hash preimage ---->               |                 | (I)
K.                 |    privB(B+C) ---->               | your private key (this struct is in both enums MakerToTakerMessages and TakerToMakerMessages)
L.               <---------------------- privC(C+A)    | (K)
M.    privA(A+B) ---->               |                 | (K)

```


### Notes on architecture

Makers are servers which run Tor hidden services. Takers connect to them.

We aim to have makers have a little state as possible. Makers are not even meant to know how many other makers there are in the route. They just offer their services, offer their fees, protect themselves from DOS, complete the coinswaps and make sure they get paid those fees.

All the big decisions are made by takers (which makes sense because takers are paying, the customer is always right etc)
Decisions like:
* how many makers in the route
* how many transactions in the multi-transaction coinswap
* how long to wait between funding txes
* the bitcoin amount in the coinswap

In this protocol its always important to as much as possible avoid DOS attack opportunities, especially against makers.


## Chris Belcher's personal roadmap for the project

* &#9745; learn rust
* &#9745; learn rust-bitcoin
* &#9745; design a protocol where all the features (vanilla coinswap, multi-tx coinswap, routed coinswap, branching routed coinswap, privkey handover) can be done, and publish to mailing list
* &#9745; code simplest possible wallet, seed phrases "generate" and "recover", no fidelity bonds, everything is sybil attackable or DOS attackable for now, no RBF
* &#9745; implement creation and signing of traditional multisig
* &#9745; code makers and takers to support simple coinswap
* &#9745; code makers and takers to support multi-transaction coinswaps without any security (e.g. no broadcasting of contract transactions)
* &#9744; code makers and takers to support multi-hop coinswaps without security
* &#9744; write more developer documentation
* &#9744; set up a solution to mirror this repository somewhere else in case github rm's it like they did youtube-dl
* &#9744; implement and deploy fidelity bonds in joinmarket
* &#9744; code security. For now watchtowers only in the same process as the main scripts
* &#9744; code fidelity bonds
* &#9744; implement coinswap fees and taker paying for miner fees
* &#9744; code federated message board seeder servers
* &#9744; add collateral inputs to receiver contract txes
* &#9744; add support for miner fees and precomputed RBF fee-bumps, so that txes can always be confirmed regardless of the block space market
* &#9744; automated tests (might be earlier in case its useful in test driven development)
* &#9744; RELEASE FOR TESTNET AND MAYBE MAINNET
* &#9744; study ecdsa-2p and implement ecdsa-2p multisig so the coinswaps can look identical to regular txes
* &#9744; add encrypted wallet files
* &#9744; add automated incremental backups for wallet files, because seed phrases aren't enough to backup these wallets
* &#9744; move wallet files and config to its own data directory ~/.teleport/
* &#9744; watchtowers in a separate process
* &#9744; reproducible builds + pin dependencies to a hash
* &#9744; break as many blockchain analysis heuristics as possible, e.g. change address detection
* &#9744; payjoin-with-coinswap with decoy UTXOs
* &#9744; abstract away the Core RPC so that its functions can done another way, for example for the taker being supported as a plugin for electrum
* &#9744; randomized locktimes, study with bayesian inference the best way to randomize them so that an individual maker learns as little information as possible from the locktime value
* &#9744; anti-DOS protocol additions for maker (not using json but some kind of binary format that is harder to DOS)

## Community

* IRC: `##coinswap` on the [freenode network](https://freenode.net/).

* Chris Belcher's work diary: https://gist.github.com/chris-belcher/ca5051285c6f8d38693fd127575be44d

