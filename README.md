# Teleport Transactions

Teleport Transactions is software aiming to improve the [privacy](https://en.bitcoin.it/wiki/Privacy) of [Bitcoin](https://en.bitcoin.it/wiki/Main_Page).

Suppose Alice has bitcoin and wants to send them with maximal privacy, so she creates a special kind of transaction. For anyone looking at the blockchain her transaction appears completely normal with her coins seemingly going from Bitcoin address A to address B. But in reality her coins end up in address Z which is entirely unconnected to either A or B.

Now imagine another user, Carol, who isn't too bothered by privacy and sends her bitcoin using a regular wallet. But because Carol's transaction looks exactly the same as Alice's, anybody analyzing the blockchain must now deal with the possibility that Carol's transaction actually sent her coins to a totally unconnected address. So Carol's privacy is improved even though she didn't change her behaviour, and perhaps had never even heard of this software.

In a world where advertisers, social media and other institutions want to collect all of Alice's and Carol's data, such privacy improvement is incredibly valuable. And the doubt added to every transaction would greatly boost the [fungibility of Bitcoin](https://en.bitcoin.it/wiki/Fungibility) and so make it a better form of money.

Project design document: [Design for a CoinSwap Implementation for Massively Improving Bitcoin Privacy and Fungibility](https://gist.github.com/chris-belcher/9144bd57a91c194e332fb5ca371d0964)

## Contents

- [State of the project](#state-of-the-project)
- [How to create a CoinSwap on regtest with yourself](#how-to-create-a-coinswap-on-regtest-with-yourself)
- [How to create a CoinSwap on networks other than regtest](#how-to-create-a-coinswap-on-networks-other-than-regtest)
- [How to recover from a failed coinswap](#how-to-recover-from-a-failed-coinswap)
- [Developer resources](#developer-resources)
- [Protocol between takers and makers](#protocol-between-takers-and-makers)
- [Notes on architecture](#notes-on-architecture)
- [Chris Belcher's personal roadmap for the project](#chris-belchers-personal-roadmap-for-the-project)
- [Community](#community)

## State of the project

The project is nearly usable, though it doesnt have all the necessary features yet. The code written so far is published for developers and power users to play around with. It doesn't have config files yet so you have to edit the source files to configure stuff. It is possible to run it on mainnet, but only the brave will attempt that, and only with small amounts.

## How to create a CoinSwap on regtest with yourself

* Install [rust](https://www.rust-lang.org/) on your machine.

* Start up Bitcoin Core in regtest mode. Make sure the RPC server is enabled with `server=1` and that rpc username and password are set with `rpcuser=yourrpcusername` and `rpcpassword=yourrpcpassword` in the configuration file.

* Download the [latest release](https://github.com/bitcoin-teleport/teleport-transactions/releases). Open the file `src/lib.rs` and edit the RPC username and password right at the top of the file. Make sure your Bitcoin Core has a wallet called `teleport`, or edit the name in the same place.

* Create three teleport wallets by running `cargo run -- --wallet-file-name=<wallet-name> generate-wallet` thrice. Instead of `<wallet-name>`, use something like `maker1.teleport`, `maker2.teleport` and `taker.teleport`.

* Use `cargo run -- --wallet-file-name=maker1.teleport get-receive-invoice` to obtain 3 addresses of the maker1 wallet, and send regtest bitcoin to each of them (amount 5000000 satoshi or 0.05 BTC in this example). Also do this for the `maker2.teleport` and `taker.teleport` wallets. Get the transactions confirmed.

* Check the wallet balances with `cargo run -- --wallet-file-name=maker1.teleport wallet-balance`. Example:

```
$ cargo run -- --wallet-file-name=maker1.teleport wallet-balance
coin             address                    type   conf    value
8f6ee5..74e813:0 bcrt1q0vn5....nrjdqljtaq   seed   1       0.05000000 BTC
d548a8..cadd5e:0 bcrt1qaylc....vnw4ay98jq   seed   1       0.05000000 BTC
604ca6..4ab5f0:1 bcrt1qt3jy....df6pmewmzs   seed   1       0.05000000 BTC
coin count = 3
total balance = 0.15000000 BTC
```

```
$ cargo run -- --wallet-file-name=maker2.teleport wallet-balance
coin             address                    type   conf    value
d33f06..30dd07:0 bcrt1qh6kq....e0tlfrzgxa   seed   1       0.05000000 BTC
8aaa89..ef5613:0 bcrt1q9vyj....plh8x37n7g   seed   1       0.05000000 BTC
383ffe..127065:1 bcrt1qlwzv....pdqtrg0xuu   seed   1       0.05000000 BTC
coin count = 3
total balance = 0.15000000 BTC
```

```
$ cargo run -- --wallet-file-name=taker.teleport wallet-balance
coin             address                    type   conf    value
5f4331..d53f14:0 bcrt1qmflt....q2ucgf2teu   seed   1       0.05000000 BTC
6252ee..d827b0:0 bcrt1qu9mk....pwpedjyl9u   seed   1       0.05000000 BTC
ac88da..e3ead6:0 bcrt1q3xdx....e7gxtcgrfg   seed   1       0.05000000 BTC
coin count = 3
total balance = 0.15000000 BTC
```

* On another terminal run a watchtower with `cargo run -- run-watchtower`. You should see the message `Starting teleport watchtower`. In the teleport project, contracts are enforced with one or more watchtowers which are required for the coinswap protocol to be secure against the maker's coins being stolen.

* On one terminal run a maker server with `cargo run -- --wallet-file-name=maker1.teleport run-yield-generator 6102`. You should see the message `Listening on port 6102`.

* On another terminal run another maker server with `cargo run -- --wallet-file-name=maker2.teleport run-yield-generator 16102`. You should see the message `Listening on port 16102`.

* On another terminal start a coinswap with `cargo run -- --wallet-file-name=taker.teleport do-coinswap 500000`. When you see the terminal messages `waiting for funding transaction to confirm` and `waiting for maker's funding transaction to confirm` then tell regtest to generate another block (or just wait if you're using testnet).

* Once you see the message `successfully completed coinswap` on all terminals then check the wallet balance again to see the result of the coinswap. Example:

```
$ cargo run -- --wallet-file-name=maker1.teleport wallet-balance
coin             address                    type   conf    value
9bfeec..0cc468:0 bcrt1qx49k....9cqqrp3kt0 swapcoin 2       0.00134344 BTC
973ab4..48f5b7:1 bcrt1qdu4j....ru3qmw4gcf swapcoin 2       0.00224568 BTC
2edf14..74c3b9:0 bcrt1qfw6z....msrsdx9sl0 swapcoin 2       0.00131088 BTC
bd6321..217707:0 bcrt1q35g8....rt6al6kz7s   seed   1       0.04758551 BTC
c6564e..40fb64:0 bcrt1qrnzc....czs840p4np   seed   1       0.04947775 BTC
08e857..c8c67b:0 bcrt1qdxdg....k7882f0ya2   seed   1       0.04808502 BTC
coin count = 6
total balance = 0.15004828 BTC
```

```
$ cargo run -- --wallet-file-name=maker2.teleport wallet-balance
coin             address                    type   conf    value
9d8895..e32645:1 bcrt1qm73u....3h6swyege3 swapcoin 3       0.00046942 BTC
7cab11..07ff62:1 bcrt1quumg....gtjs29jt8t swapcoin 3       0.00009015 BTC
289a13..ab4672:0 bcrt1qsavn....t5dsac43tl swapcoin 3       0.00444043 BTC
9bfeec..0cc468:1 bcrt1q24f8....443ts4rzz0   seed   2       0.04863932 BTC
973ab4..48f5b7:0 bcrt1q5klz....jhhtlyjpkg   seed   2       0.04773708 BTC
2edf14..74c3b9:1 bcrt1qh2aw....7xx8wft658   seed   2       0.04867188 BTC
coin count = 6
total balance = 0.15004828 BTC
```

```
$ cargo run -- --wallet-file-name=taker.teleport wallet-balance
coin             address                    type   conf    value
9d8895..e32645:0 bcrt1qevgn....6nhl2yswa7   seed   3       0.04951334 BTC
7cab11..07ff62:0 bcrt1qxs5f....0j8khru45s   seed   3       0.04989261 BTC
289a13..ab4672:1 bcrt1qkwka....g9ts2ch392   seed   3       0.04554233 BTC
bd6321..217707:1 bcrt1qat5h....vytquawwke swapcoin 1       0.00239725 BTC
c6564e..40fb64:1 bcrt1qshwp....3x8qjtwdf6 swapcoin 1       0.00050501 BTC
08e857..c8c67b:1 bcrt1q37lf....5tvqndktw6 swapcoin 1       0.00189774 BTC
coin count = 6
total balance = 0.14974828 BTC
```

## How to create a CoinSwap on networks other than regtest

* This is done in pretty much the same way as on the regtest network. On public networks you don't always have to coinswap with yourself by creating and funding multiple wallets, instead you could coinswap with other users out there.

* Teleport detects which network it's on by asking the Bitcoin node it's connected to via json-rpc. So to switch between networks like regtest, signet, testnet or mainnet (for the brave), make sure the RPC host and port are correct in `src/lib.rs`.

* You will need Tor running on the same machine, then open the file `src/directory_servers.rs` and make sure the const `TOR_ADDR` has the correct Tor port.

* To see all the advertised offers out there, use the `download-offers` subroutine: `cargo run -- download-offers`:

```
$ cargo run -- download-offers
n   maker address                                                          max size     min size     abs fee      amt rel fee  time rel fee minlocktime
0   5wlgs4tmkc7vmzsqetpjyuz2qbhzydq6d7dotuvbven2cuqjbd2e2oyd.onion:6102    348541       10000        1000         10000000     100000       48
1   eitmocpmxolciziezpp6vzvhufg6djlq2y4oxpm436w5kpzx4tvfgead.onion:16102   314180       10000        1000         10000000     100000       48
```

* To run a yield generator (maker) on any network apart from regtest, you will need to create a tor hidden service for your maker. Search the web for "setup tor hidden service", a good article is [this one](https://www.linuxjournal.com/content/tor-hidden-services). When you have your hidden service hostname, copy it into the field near the top of the file `src/maker_protocol.rs`. Run with `cargo run -- --wallet-file-name=maker.teleport run-yield-generator` (note that you can omit the port number, the default port is 6102, specifying a different port number is only really needed for regtest where multiple makers are running on the same machine).

* After a successful coinswap created with `do-coinswap`, the coins will still be in the wallet. You can send them out somewhere else using the command `direct-send` and providing the coin(s). For example `cargo run -- --wallet-file-name=taker.teleport direct-send max <destination-address> 9bfeec..0cc468:0`. Coins in the wallet can be found by running `wallet-balance` as above.

## How to recover from a failed coinswap

* CoinSwaps can sometimes fail. Nobody will lose their funds, but they can have their time wasted and have spent miner fees without achieving any privacy gain (or even making their privacy worse, at least until scriptless script contracts are implemented). Everybody is incentivized so that this doesnt happen, and takers are coded to be very persistent in reestablishing a connection with makers before giving up, but sometimes failures will still happen.

* The major way that CoinSwaps can fail is if a taker locks up funds in a 2-of-2 multisig with a maker, but then that maker becomes non-responsive and so the CoinSwap doesn't complete. The taker is left with their money in a multisig and has to use their pre-signed contract transaction to get their money back after a timeout. This section explains how to do that.

* Failed or incomplete coinswaps will show up in wallet display in another section: `cargo run -- --wallet-file-name=taker.teleport wallet-balance`. Example:

```
= spendable wallet balance =
coin             address                    type   conf    value
9cd867..f80d57:1 bcrt1qgscq....xkxg68mq02   seed   212     0.11103591 BTC
13a0f4..947ab8:1 bcrt1qwfyl....wf0eyf5kuf   seed   212     0.07666832 BTC
901514..10713b:0 bcrt1qghs3....qsg8al2ch4   seed   95      0.04371040 BTC
2fe664..db1a59:0 bcrt1ql83h....hht5vc97dl   seed   94      0.50990000 BTC
coin count = 4
total balance = 0.74131463 BTC
= incomplete coinswaps =
coin             type     preimage locktime/blocks conf    value
10149d..0d0314:1 timelock unknown         9        24      0.00029472 BTC
b36e34..51fa3b:0 timelock unknown         9        24      0.00905248 BTC
2b2e2d..c6db9e:1 timelock unknown         9        24      0.00065280 BTC
outgoing balance = 0.01000000 BTC
hashvalue = a4c2fe816bf18afb8b1861138e57a51bd70e29d4
```

* In this example there is an incomplete coinswap involving three funding transactions, we must take the hashvalue `a4c2fe816bf18afb8b1861138e57a51bd70e29d4` and pass it to the main subroutine: `cargo run -- --wallet-file-name=taker.teleport recover-from-incomplete-coinswap a4c2fe816bf18afb8b1861138e57a51bd70e29d4`.

* Displaying the wallet balance again (`cargo run -- --wallet-file-name=taker.teleport wallet-balance`) after the transactions are broadcast will show the coins in the timelocked contracts section:

```
= spendable wallet balance =
coin             address                    type   conf    value
9cd867..f80d57:1 bcrt1qgscq....xkxg68mq02   seed   212     0.11103591 BTC
13a0f4..947ab8:1 bcrt1qwfyl....wf0eyf5kuf   seed   212     0.07666832 BTC
901514..10713b:0 bcrt1qghs3....qsg8al2ch4   seed   95      0.04371040 BTC
2fe664..db1a59:0 bcrt1ql83h....hht5vc97dl   seed   94      0.50990000 BTC
coin count = 4
total balance = 0.74131463 BTC
= live timelocked contracts =
coin             hashvalue  timelock conf    locked?  value
452a99..95f364:0 a4c2fe81.. 9        0       locked   0.00904248 BTC
dcfd27..56108a:0 a4c2fe81.. 9        0       locked   0.00064280 BTC
6a8328..f2f5ae:0 a4c2fe81.. 9        0       locked   0.00028472 BTC
```

* Right now these coins are protected by timelocked contracts which are not yet spendable, but after a number of blocks they will be added to the spendable wallet balance, where they can be spent either in a coinswap or with `direct-send`.


## Developer resources

### How CoinSwap works

In a two-party coinswap, Alice and Bob can swap a coin in a non-custodial way, where neither party can steal from each other. At worst, they can waste time and miner fees.

To start a coinswap, Alice will obtain one of Bob's public keys and use that to create a 2-of-2 multisignature address (known as Alice's coinswap address) made from Alice's and Bob's public keys. Alice will create a transaction (known as Alice's funding transaction) sending some of her coins (known as the coinswap amount) into this 2-of-2 multisig, but before she actually broadcasts this transaction she will ask Bob to use his corresponding private key to sign a transaction (known as Alice contract transaction) which sends the coins back to Alice after a timeout. Even though Alice's coins would be in a 2-of-2 multisig not controlled by her, she knows that if she broadcasts her contract transaction she will be able to get her coins back even if Bob disappears.

Soon after all this has happened, Bob will do a similar thing but mirrored. Bob will obtain one of Alice's public keys and from it Bob's coinswap address. Bob creates a funding transaction paying to it the same coinswap amount, but before he broadcasts it he gets Alice to sign a contract transaction which sends Bob's coins back to him after a timeout.

At this point both Alice and Bob are able to broadcast their funding transactions paying coins into multisig addresses, and if they want they can get those coins back by broadcasting their contract transactions and waiting for the timeout. The trick with coinswap is that the contract transaction script contains a second clause: it is also possible for the other party to get the coins by providing a hash preimage (e.g. HX = sha256(X)) without waiting for a timeout. The effect of this is that if the hash preimage is revealed to both parties then the coins in the multisig addresses have transferred possession off-chain to the other party who originally didn't own those coins.

When the preimage is not known, Alice can use her contract transaction to get coins from Alice's multisig address after a timeout, and Bob can use his contract transaction to get coins from the Bob multisig address after a timeout. After the preimage is known, Alice can use Bob's contract transaction and the preimage to get coins from Bob's multisig address, and also Bob can use Alice's contract transaction and the preimage to get the coins from Alice's multisig address.

Here is a diagram of Alice and Bob's coins and how they swap possession after a coinswap:
```
                                              Alice after a timeout
                                             /
                                            /
Alice's coins ------> Alice coinswap address
                                            \
                                             \
                                              Bob with knowledge of the hash preimage


                                          Bob after a timeout
                                         /
                                        /
Bob's coins ------> Bob coinswap address
                                        \
                                         \
                                          Alice with knowledge of the hash preimage
```

If Alice attempts to take the coins from Bob's coinswap address using her knowledge of the hash preimage and Bob's contract transaction, then Bob will be able to read the value of the hash preimage from the blockchain, and use it to take the coins from Alice's coinswap address. This happens in the worst case, but in virtually all real-life situations it will never get to that point. The contracts usually always stay unbroadcasted.

So at this point we've reached a situation where if Alice gets paid then Bob cannot fail to get paid, and vice versa. Now to save time and miner fees, the party which started with knowledge of the hash preimage will reveal it, and both parties will send each other their private keys corresponding to their public keys in the 2-of-2 multisigs. After this private key handover Alice will know both private keys in the relevant multisig address, and so those coins are in her sole possession. The same is true for Bob.

```
Alice's coins ----> Bob's address

Bob's coins ----> Alice's address
```

In a successful coinswap, Alice's and Bob's coinswap addresses transform off-chain to be possessed by the other party


[Bitcoin's script](https://en.bitcoin.it/wiki/Script) is used to code these timelock and hashlock conditions. Diagrams of the transactions:
```
= Alice's funding transaction =
Alice's inputs -----> multisig (Alice pubkey + Bob pubkey)

= Bob's funding transaction =
Bob's inputs -----> multisig (Bob pubkey + Alice pubkey)

= Alice's contract transaction=
multisig (Alice pubkey + Bob pubkey) -----> contract script (Alice pubkey + timelock OR Bob pubkey + hashlock)

= Bob's contract transaction=
multisig (Bob pubkey + Alice pubkey) -----> contract script (Bob pubkey + timelock OR Alice pubkey + hashlock)
```

The contract transactions are only ever used if a dispute occurs. If all goes well the contract transactions never hit the blockchain and so the hashlock is never revealed, and therefore the coinswap improves privacy by delinking the transaction graph.

The party which starts with knowledge of the hash preimage must have a longer timeout, this means there is always enough time for the party without knowledge of the preimage to read the preimage from the blockchain and get their own transaction confirmed.

This explanation describes the simplest form of coinswap. On its own it isn't enough to build a really great private system. For more building blocks read the [design document of this project](https://gist.github.com/chris-belcher/9144bd57a91c194e332fb5ca371d0964).

### Notes on architecture

Makers are servers which run Tor hidden services (or possibly other hosting solutions in case Tor ever stops working). Takers connect to them. Makers never connect to each other.

Diagram of connections for a 4-hop coinswap:
```
        ---- Bob
       /
      /
Alice ------ Charlie
      \
       \
        ---- Dennis
```

The coinswap itself is multi-hop:

```
Alice ===> Bob ===> Charlie ===> Dennis ===> Alice
```

Makers are not even meant to know how many other makers there are in the route. They just offer their services, offer their fees, protect themselves from DOS, complete the coinswaps and make sure they get paid those fees. We aim to have makers have as little state as possible, which should help with DOS-resistance.

All the big decisions are made by takers (which makes sense because takers are paying, and the customer is always right.)
Decisions like:
* How many makers in the route
* How many transactions in the multi-transaction coinswap
* How long to wait between funding txes
* The bitcoin amount in the coinswap

In this protocol it's always important to as much as possible avoid DOS attack opportunities, especially against makers.


### Protocol between takers and makers

Alice is the taker, Bob, Charlie and Dennis are makers. For a detailed explanation including definitions see the mailing list email [here](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-October/018221.html). That email should be read first and then you can jump back to the diagram below when needed while reading the code.

Protocol messages are defined by the structs found in `src/messages.rs` and serialized into json with rust's serde crate.

```
 | Alice           | Bob             | Charlie         |  Dennis         | message, or (step) if repeat
 |=================|=================|=================|=================|
0. AB/A htlc     ---->               |                 |                 | sign senders contract
1.               <---- AB/A htlc B/2 |                 |                 | senders contract sig
2.    ************** BROADCAST AND MINE ALICE FUNDING TX *************** |
3.    A fund     ---->               |                 |                 | proof of funding
4.               <----AB/B+BC/B htlc |                 |                 | sign senders and receivers contract
5. BC/B htlc     ---------------------->               |                 | (0)
6.               <---------------------- BC/B htlc C/2 |                 | (1)
7. AB/B+BC/B A+C/2--->               |                 |                 | senders and receivers contract sig
8.    ************** BROADCAST AND MINE BOB FUNDING TX ***************   |
A.    B fund     ---------------------->               |                 | (3)
B.               <----------------------BC/C+CD/C htlc |                 | (4)
C. CD/C htcl     ---------------------------------------->               | (0)
D.               <---------------------------------------- CD/C htlc D/2 | (1)
E. BC/C htlc     ---->               |                 |                 | sign receiver contract
F.               <---- BC/C htlc B/2 |                 |                 | receiver contract sig
G.BC/C+CD/C B+D/2----------------------->              |                 | (7)
H.   ************** BROADCAST AND MINE CHARLIE FUNDING TX ************** |
I.   C fund      ---------------------------------------->               | (3)
J.               <----------------------------------------CD/D+DA/D htlc | (4)
K. CD/D htlc     ---------------------->               |                 | (E)
L.               <---------------------- CD/D htlc C/2 |                 | (F)
M.CD/D+DA/D C+D/2---------------------------------------->               | (7)
N.   ************** BROADCAST AND MINE DENNIS FUNDING TX *************** |
O. DA/A htlc     ---------------------------------------->               | (E)
P.               <---------------------------------------- DA/A htlc D/2 | (F)
Q. hash preimage ---->               |                 |                 | hash preimage
R.               <---- privB(B+C)    |                 |                 | privkey handover
S.    privA(A+B) ---->               |                 |                 | (R)
T. hash preimage ---------------------->               |                 | (Q)
U.               <---------------------- privC(C+D)    |                 | (R)
V.    privB(B+C) ---------------------->               |                 | (R)
W. hash preimage ---------------------------------------->               | (Q)
X                <---------------------------------------- privD(D+A)    | (R)
Y.    privC(C+D) ---------------------------------------->               | (R)
```

#### Note on terminology: Sender and Receiver

In the codebase and protocol documentation the words "Sender" and "Receiver" are used. These refer
to either side of a coinswap address. The entity which created a transaction paying into a coinswap
address is called the sender, because they sent the coins into the coinswap address. The other
entity is called the receiver, because they will receive the coins after the coinswap is complete.

### Further reading

* [Waxwing's blog post from 2017 about CoinSwap](https://web.archive.org/web/20200524041008/https://joinmarket.me/blog/blog/coinswaps/)

* [gmaxwell's original coinswap writeup from 2013](https://bitcointalk.org/index.php?topic=321228.0). It explains how CoinSwap actually works. If you already understand how Lightning payment channels work then CoinSwap is similar.

* [Design for improving JoinMarket's resistance to sybil attacks using fidelity bonds](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af/). Document explaining the concept of fidelity bonds and how they provide resistance against sybil attacks.



## Chris Belcher's personal roadmap for the project

* &#9745; learn rust
* &#9745; learn rust-bitcoin
* &#9745; design a protocol where all the features (vanilla coinswap, multi-tx coinswap, routed coinswap, branching routed coinswap, privkey handover) can be done, and publish to mailing list
* &#9745; code the simplest possible wallet, seed phrases "generate" and "recover", no fidelity bonds, everything is sybil attackable or DOS attackable for now, no RBF
* &#9745; implement creation and signing of traditional multisig
* &#9745; code makers and takers to support simple coinswap
* &#9745; code makers and takers to support multi-transaction coinswaps without any security (e.g. no broadcasting of contract transactions)
* &#9745; code makers and takers to support multi-hop coinswaps without security
* &#9745; write more developer documentation
* &#9744; set up a solution to mirror this repository somewhere else in case github rm's it like they did youtube-dl
* &#9745; implement and deploy fidelity bonds in joinmarket, to experiment and gain experience with the concept
* &#9745; add proper error handling to this project, as right now most of the time it will exit on anything unexpected
* &#9745; code security, recover from aborts and deveations
* &#9745; implement coinswap fees and taker paying for miner fees
* &#9745; add support for connecting to makers that arent on localhost, and tor support
* &#9745; code federated message board seeder servers
* &#9745; ALPHA RELEASE FOR TESTNET, REGTEST, SIGNET AND MAINNET (FOR THE BRAVE ONES)
* &#9745; have watchtower store data in a file, not in RAM
* &#9744; study ecdsa-2p and implement ecdsa-2p multisig so the coinswaps can look identical to regular txes
* &#9744; have taker store the progress of a coinswap to file, so that the whole process can be easily paused and started
* &#9744; add automated incremental backups for wallet files, because seed phrases aren't enough to back up these wallets
* &#9744; code fidelity bonds
* &#9744; add support precomputed RBF fee-bumps, so that txes can always be confirmed regardless of the block space market
* &#9744; automated tests (might be earlier in case its useful in test driven development)
* &#9744; move wallet files and config to its own data directory ~/.teleport/
* &#9744; add collateral inputs to receiver contract txes
* &#9744; implement encrypted contract txes for watchtowers, so that watchtowers can do their job without needing to know the addresses involved
* &#9744; implement branching and merging coinswaps for takers, so that they can create coinswaps even if they just have one UTXO
* &#9744; add encrypted wallet files
* &#9744; reproducible builds + pin dependencies to a hash
* &#9744; break as many blockchain analysis heuristics as possible, e.g. change address detection
* &#9744; create a GUI for taker
* &#9744; find coins landing on already-used addresses and freeze them, to resist the [forced address reuse attack](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
* &#9744; payjoin-with-coinswap with decoy UTXOs
* &#9744; convert contracts which currently use script to instead use adaptor signatures, aiming to not reveal contracts in the backout case
* &#9744; create a [web API](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/JSON-RPC-API-using-jmwalletd.md) similar to the [one in joinmarket](https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/978)
* &#9744; randomized locktimes, study with bayesian inference the best way to randomize them so that an individual maker learns as little information as possible from the locktime value
* &#9744; anti-DOS protocol additions for maker (not using json but some kind of binary format that is harder to DOS)
* &#9744; abstract away the Core RPC so that its functions can be done in another way, for example for the taker being supported as a plugin for electrum
* &#9744; make the project into a plugin which can be used by other wallets to do the taker role, try to implement it for electrum wallet

## Community

* IRC channel: `#coinswap`. Logs available [here](http://gnusha.org/coinswap/). Accessible on the [libera IRC network](https://libera.chat/) at `irc.libera.chat:6697 (TLS)` and on the [webchat client](https://web.libera.chat/#coinswap). Accessible anonymously to Tor users on the [Hackint network](https://www.hackint.org/transport/tor) at `ncwkrwxpq2ikcngxq3dy2xctuheniggtqeibvgofixpzvrwpa77tozqd.onion:6667`.

* Chris Belcher's work diary: https://gist.github.com/chris-belcher/ca5051285c6f8d38693fd127575be44d

