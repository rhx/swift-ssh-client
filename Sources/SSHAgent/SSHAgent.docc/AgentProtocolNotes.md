# Agent Protocol Notes

Understand how the package maps OpenSSH agent messages to Swift types.

## Overview

The SSH agent protocol uses a four-byte big-endian length prefix followed by a message body. `SSHAgent` builds those frames for identity and signing requests, and `SSHAgentResponseHandler` accumulates inbound bytes until a complete response frame is available.

Identity responses are parsed into `SSHAgentKey` values by decoding the key blob and comment for each entry. Signature responses are validated against the expected response type before the embedded signature payload is extracted. RSA signatures are then converted into the `NIOSSHSignature` cases expected by the currently selected `swift-nio-ssh` branch.

The implementation favours explicit parsing over generic decoding helpers because the on-the-wire representation is small, fixed, and performance-sensitive. That makes the protocol easier to audit when support for additional key algorithms is added.

## Topics

### Relevant Symbols

- ``SSHAgent/requestIdentities()``
- ``SSHAgent/requestSignature(for:usingKey:flags:)``
