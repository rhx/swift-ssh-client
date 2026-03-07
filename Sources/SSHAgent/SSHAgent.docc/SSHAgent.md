# ``SSHAgent``

Communicate with the local SSH agent and adapt agent-backed keys to `NIOSSH`.

## Overview

`SSHAgent` implements the OpenSSH agent message framing needed to list identities and request signatures over `SSH_AUTH_SOCK`. It exposes a small async API that turns agent responses into `SSHAgentKey` values and, when needed, wraps those keys in `NIOSSHPrivateKey` values whose signing operations are delegated back to the agent.

The target keeps the raw protocol parsing in one place so higher-level code can work with Swift types instead of hand-built binary messages. It also preserves agent-specific behaviour such as RSA signing flags and response parsing rules.

## Topics

### Core Types

- ``SSHAgent``
- ``SSHAgentKey``
- ``SSHAgentError``
- ``SSHAgentMessageType``
- ``SSHAgentSignFlags``
- ``SendableData``

### Signing Support

- ``SSHAgent/createNIOSSHPrivateKey(for:)``
- ``SSHAgent/requestSignature(for:usingKey:flags:)``
- ``SSHAgentPrivateKey``

### Protocol Handling

- ``SSHAgent/requestIdentities()``
- <doc:AgentProtocolNotes>
