# Forwarding Traffic

Expose a local listening socket and tunnel accepted connections through the SSH transport.

## Overview

`PortForwardingServer` binds a local listener and opens a `direct-tcpip` child channel for each accepted inbound connection. The forwarding pipeline uses `SSHWrapperHandler` and a matched pair of `GlueHandler` instances to bridge raw `ByteBuffer` traffic to and from SSH channel messages.

This package currently implements local forwarding. Remote forwarding and arbitrary global requests are still lower-level concerns that callers would need to build directly on `NIOSSH`.

## Topics

### Forwarding Types

- ``PortForwardingConfiguration``
- ``PortForwardingServer``
- ``SSHWrapperHandler``
- ``GlueHandler``

