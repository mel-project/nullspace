# xirtam-crypt

xirtam-crypt provides small, opinionated wrappers around common crypto primitives with consistent construction and serialization (including human-readable JSON via base64).

| Module | Types | Primitive |
| --- | --- | --- |
| `dh` | `DhPublic`, `DhSecret` | X25519 Diffie-Hellman |
| `signing` | `SigningPublic`, `SigningSecret`, `Signature` | Ed25519 signatures |
| `symmetric` | `SymmetricKey` | ChaCha20-Poly1305 |
| `hash` | `Hash` | BLAKE3 |

Here is a minimal signing example that generates a key, signs a message, and verifies it with the public key:

```rust
use xirtam_crypt::signing::SigningSecret;

let secret = SigningSecret::random();
let public = secret.public_key();
let msg = b"hello";
let sig = secret.sign(msg);

public.verify(&sig, msg).expect("valid signature");
```
