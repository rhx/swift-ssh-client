# Authentication Flow

Choose an authentication strategy and understand how the client falls back when a method is unavailable.

## Overview

`SSHClient` delegates user authentication to `CompositeAuthDelegate`, which first attempts public-key authentication through `SSHAgent` and only then falls back to password authentication when a password is available. This keeps the more secure agent-backed path first while still supporting unattended or scripted password-based sessions.

Agent-backed signing is implemented with `NIOSSHPrivateKey` values whose signing callback calls back into `SSHAgent`. That means the client never needs to import private key material into its own process. The server only sees the usual SSH user-authentication exchange, while the actual signature generation stays inside the agent.

`AcceptAllHostKeysDelegate` currently accepts any server key. That behaviour keeps the sample client easy to use during development, but it also means host authenticity is not verified. Applications that need host key pinning or known-host checks should replace that delegate with stricter validation.

