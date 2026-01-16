# Network architecture

## Participants

There are three kinds of participants in the Xirtam protocol: **clients**, **servers**, and the **directory**.

### Clients

Clients are end-user devices. They:
- hold device keys and a certificate chain anchored to a username
- talk to servers for mailbox access and device key publication
- talk to the directory for username and server resolution

Xirtam is an *end-to-end encrypted* chat system. This means that generally, clients are the only place where plaintext messages exist. Servers and the directory only see encrypted payloads plus the routing metadata required to deliver them.

### Servers

Servers are "concierge servers" for client devices. Unlike Matrix homeservers or email servers, these are *untrusted* entities with, most importantly, no power over the user identities, which are controlled entirely by the directory service. 

Servers:
- host mailboxes (DM, group message, group management) 
- enforce ACLs based on device auth tokens
- publish medium-term device keys for envelope encryption
- serve username certificate chains

Unlike in federated protocols, servers do not relay to each other; they only accept requests from clients. "Cross-server" communication is done by a sender posting to a recipient's server mailbox. For privacy and efficiency, though, servers may offer a **proxy service** that allows clients to talk to other servers through them; this is especially useful if the clients are behind a restricted network (say, behind the Great Firewall of China).

Servers also serve as read-replicas of the directory, so that other than during the initial registration process, clients do not add any load to the global directory.

### Directory service

The directory is a centralized, append-only registry that is the root of trust for the entire public key infrastructure of Xirtam. It maps:
- username -> server name + root cert hash
- server name -> server URLs + server public key

This is the *only point of centralized trust* in the system, similar in position to Tor's directory service, so several precautions are taken to minimize this trust as much as possible:
- everything is in transparency logs, and all queries come with inclusion proofs that are client-side verified
- anybody can mirror and serve the entire directory, and servers are encouraged to do so
- authentication is by signing the root of the entire transparency log, which is fetched by clients before making specific queries, which makes any attempt at equivocation (e.g. serving one binding to Bob and another binding to Alice for the same name), and thus any MitM attack, extremely difficult and highly evident

An interesting feature is that the directory API intentionally imitates a blockchain, including a blockchain's performance and cost characteristics. For example, it enforces expensive updates (PoW) to limit abuse, provides a signed snapshot + header chain for verifiable sync, and is entirely permissionless and offers no manual "account recovery" or similar procedures. The purpose is to force the rest of the ecosystem to design UX, protocols, etc in such a way that the directory can seamlessly be replaced by a light-client-first blockchain like [Mel](https://melproject.org), once such a blockchain exists and has reasonable economic security.

**Note**: it would not be a good idea at the current stage to use a blockchain for the directory, because mainstream blockchains like Ethereum do not have good enough light client support to avoid completely trusting an RPC provider. That would be *significantly* worse security and decentralization than a tamper-evident directory service.

## Identity Model

- **Username**: user identifier like `@user_01`.
- **Server name**: server identifier like `~serv_01`.
- **User descriptor**: directory entry for a username.
- **Server descriptor**: directory entry for a server.
- **Certificate chain**: ordered device certs rooted at a username's root cert hash.

Clients resolve a username via the directory, then fetch the certificate chain from the server and verify it against the root cert hash.
