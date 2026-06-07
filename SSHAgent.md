# SSH Agent Integration

## Overview

`swift-ssh-client` delegates public-key user-authentication signatures to a local
`ssh-agent`, so private key material never has to be imported into the client process.

This relies on `NIOSSHPrivateKey(publicKey:signingCallback:)` in the
[`rhx/swift-nio-ssh`](https://github.com/rhx/swift-nio-ssh/) fork, which exposes the
extension point needed to hand user-authentication signing back to the agent.

## How It Works

`PublicKeyAgentDelegate` asks the local agent for a suitable public key, creates an `NIOSSHPrivateKey` backed by that public key plus a signing callback, and hands that key to `NIOSSH` as a normal public-key authentication offer.

When `NIOSSH` needs a user-authentication signature, it invokes the signing callback. The callback requests a signature from `ssh-agent`, converts the returned SSH wire-format signature into an `NIOSSHSignature`, and returns it to `NIOSSH`.

This means:

- key discovery still comes from `SSH_AUTH_SOCK`
- private key operations stay in the agent
- password fallback still works through `CompositeAuthDelegate`

## Dependency Requirement

This behaviour depends on the forked `swift-nio-ssh` branch configured in [`Package.swift`](Package.swift):

- `https://github.com/rhx/swift-nio-ssh/`, branch `rsa-agent`

RSA support is optional and is enabled with the `RSA` SwiftPM trait in both packages:

- `swift build --traits RSA`
- `swift test --traits RSA`

If the package is moved back to upstream `apple/swift-nio-ssh` without these branch changes, SSH agent signing delegation will stop working until the same API is available there.

## Supported Key Types

The current agent-signing path is implemented for:

- Ed25519
- ECDSA P-256
- ECDSA P-384
- ECDSA P-521
- RSA with `rsa-sha2-256`
- RSA with `rsa-sha2-512`
