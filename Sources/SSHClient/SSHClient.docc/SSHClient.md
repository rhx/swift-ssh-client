# ``SSHClient``

A high-level Swift API for SSH sessions, remote commands, interactive shells, and local port forwarding.

## Overview

`SSHClient` builds on `NIOSSH` and the local `SSHAgent` module to provide a small async API for common client-side SSH work. The library manages the connection channel, negotiates user authentication, opens session channels for commands or shells, and can also create direct TCP/IP forwarding channels for local listeners.

The target is designed for applications that want SSH support without rebuilding the lower-level `NIOSSH` pipeline for each use case. It keeps the transport concerns explicit while still exposing a concise surface for connection management and session execution.

## Topics

### Essentials

- ``SSHClient``
- ``SSHClientConfiguration``
- ``CommandResult``
- ``SSHClientError``

### Interactive and Non-Interactive Sessions

- ``SSHClient/connect()``
- ``SSHClient/executeCommand(_:)``
- ``SSHClient/startInteractiveShell(term:terminalCharacterWidth:terminalRowHeight:terminalPixelWidth:terminalPixelHeight:terminalModes:)``
- <doc:RunningSessions>

### Port Forwarding

- ``PortForwardingConfiguration``
- ``PortForwardingServer``
- ``SSHClient/startPortForwarding(_:)``
- <doc:ForwardingTraffic>

### Authentication and Internals

- <doc:AuthenticationFlow>
- ``SSHWrapperHandler``
- ``GlueHandler``

