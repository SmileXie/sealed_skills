# M1 temporary convention: `pack.author_pub` holds the device public key

> **SUPERSEDED (M2):** The placeholder no longer exists. Both the license server and the
> local `seal trial` path now put the real author Ed25519 public key in `pack.author_pub`,
> and `SealedCore` verifies the manifest with that key. This note is kept only for history.

## What the placeholder is

In M1, the local trial license issued by `@sealed/seal-cli` (`makeTrialLicense`) sets
`payload.pack.author_pub` to the requesting **device** X25519 public key (base64url), i.e.
the same bytes as `payload.dev`. It is not the author's Ed25519 signing public key.

## Why

- M1 has no authorization server: the trial license is minted locally against a development
  signing key and there is no trusted channel carrying the real author key.
- The trial license only needs to unlock the trial entries for one device, so the device key is
  a convenient, already-available placeholder that keeps the license shape valid.
- The manifest signature is still produced and verified with the author key; only the
  `author_pub` field inside the trial license payload is the placeholder.

## M2 replacement plan

The M2 license server will fill `pack.author_pub` with the real author Ed25519 public key when it
issues or renews a license, so clients can verify the pack manifest signature directly from the
license. The local trial path will then either be removed or receive the author key from the
server. Consumers must not assume `author_pub` is an author key while the M1 placeholder is in
use.
