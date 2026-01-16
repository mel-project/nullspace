# xirtam: an experimental confederal protocol

[📖 Protocol docs](https://mel-project.github.io/xirtam-core/#/)

Xirtam (this name is provisional!) is a **confederal** end-to-end chat system. A confederal protocol is *somewhat* similar to a federated protocol like Matrix in that we use a server-client architecture, but we avoid having one gigantic server and instead allow anyone to join the network with their own server. 

There are two critical differences though:
- **User sovereignty**: end-users, not servers, control root-of-trust information like public keys, as well as routing information like which server they're currently hosted at. These two pieces of information allow a user to *avoid cryptographic trust in servers* and *costlessly switch between servers*, which is not possible in a federated system like email or Matrix.
- **No server-to-server protocol**: when a client needs to interact with a client hosted at a different server, it *talks directly to that server*. A separate server-to-server federation protocol (notoriously complex in the case of Matrix) is entirely avoided. Since the servers don't need constant interconnection to form a single network; the network is only "loosely" connected by accepting the same user-sovereign authentication scheme. (This is also the origin of the "confederal" name, since confederations are more loosely organized than federations.)

[This blogpost](https://nullchinchilla.substack.com/p/confederal) provides some context on why confederal protocols are superior to both federated and "fully" peer-to-peer protocols, since they combine essentially all the advantages of a centralized or federated system with decentralized trust.

## Design features

Some notable design features:
- SimpleX-like unidirectional mailboxes for DMs
- An very easy-to-implement wire protocol based on JSON-RPC long-polling
- Robust high-level client library that abstracts over all encryption and storage, inspired by Telegram's TDLib
- [**Novel end-to-end encryption system**](e2ee.md) that avoids "ratcheting" to achieve better performance and robustness, plus a much simpler implementation. E2EE is always-on and performant, even for large groups.

## Implementation progress

- [x] Directory RPC + PoW updates + header sync (server + dirclient)
- [x] Server RPC + mailbox storage/ACLs + device auth
- [x] Core structs: usernames, server descriptors, certificates, message kinds
- [x] DM encryption format 
- [x] MVP group protocol (group IDs, rekeying, membership control)
- [ ] Advanced group features (directory naming, server migration)
- [ ] Attachments / file transfers
- [ ] PFPs, group names, and other quality of life features
- [ ] 1-to-1 voice calls
- [ ] Group voice calls
- [ ] Discord-like "communities" with fine-grained ACLs, channels, etc