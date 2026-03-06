# ssh-client

A modern, high-level SSH client for Swift, built on top of [SwiftNIO](https://github.com/apple/swift-nio)
and [SwiftNIO SSH](https://github.com/apple/swift-nio-ssh).

## What is ssh-client?

`ssh-client` provides a convenient, async-aware API for performing SSH operations in Swift.
It abstracts the complexity of the underlying `NIOSSH` implementation while providing built-in support
for common tasks like remote command execution, port forwarding, and authentication via local SSH agents.

The project is structured into three main components:

- **SSHAgent**: A standalone implementation of the SSH agent protocol.
- **SSHClient**: A high-level client library for managing SSH connections and sessions.
- **ssh-client (CLI)**: A command-line tool for using the client directly from the terminal.

## What does ssh-client support?

- **Command Execution**: Execute remote commands and capture stdout, stderr, and exit status.
- **Interactive Shells**: Open a remote login shell with a pseudo-terminal when no command is supplied.
- **Direct Port Forwarding**: Support for local port forwarding (Direct TCP/IP) to tunnel traffic through SSH.
- **SSH Agent Integration**: Automatic discovery and use of keys from local SSH agents via `SSH_AUTH_SOCK`.
- **Key Support**: Support for Ed25519, RSA, and ECDSA (P-256/384/521) keys.
- **Authentication Fallback**: Support for composite authentication, falling back from public-key to password authentication.
- **Async/Await**: Modern API utilising Swift's structured concurrency.

## How do I use ssh-client?

### User Authentication

`ssh-client` uses a `CompositeAuthDelegate` to handle authentication.
It will first attempt to use available keys from your local SSH agent.
If agent authentication is unavailable or fails, it can fall back to
password-based authentication if a password is provided in the configuration.

```swift
let config = SSHClientConfiguration(
    host: "example.com",
    username: "user",
    password: "optional-password",
    debug: false
)
let client = SSHClient(configuration: config)
```

> **Note on SSH Agent Signing**: When built against the `ssh-agent` branch of `rhx/swift-nio-ssh`, `ssh-client` delegates public-key user-authentication signatures to `ssh-agent`, so private key material remains in the agent. See [SSHAgent.md](SSHAgent.md) for the current status and key-type limitations.

### Command Execution

Executing a command is straightforward using the `executeCommand` method,
which returns a `CommandResult` containing the exit status and output data.

```swift
try await client.connect()
let result = try await client.executeCommand("ls -la /tmp")

print("Exit status: \(result.exitStatus)")
print("Standard Output: \(String(data: result.output, encoding: .utf8) ?? "")")
```

### Interactive Shells

If you omit the remote command, `ssh-client` opens an interactive shell session
and requests a pseudo-terminal, similar to the standard `ssh` command-line tool.

### Direct Port Forwarding
You can establish local port forwarding to a remote target through the SSH tunnel.

```swift
let forwardingConfig = PortForwardingConfiguration(
    bindHost: "127.0.0.1",
    bindPort: 8080,
    targetHost: "internal-database.local",
    targetPort: 5432
)

let server = try await client.startPortForwarding(forwardingConfig)
// This will start the local server and begin forwarding connections
try await server.run().get()
```

### Channel Events

The underlying `SSHClient` handles `NIOSSH` channel events automatically,
specifically managing session channels for command execution and `directTCPIP`
channels for port forwarding.

### Half Closure

The client supports half-closure on session channels, allowing it to wait
for the remote side to finish sending data even after the local side has finished
its input (essential for certain command-line utilities).

### Remote Port Forwarding and Global Requests

Support for remote port forwarding (Reverse Tunneling) and arbitrary global requests
is currently not implemented in the high-level `SSHClient` API, though the underlying
`NIOSSH` framework provides the necessary primitives.

## Command Line Interface

The package includes a CLI tool as an example that mirrors common `ssh` command
functionality:

```bash
# Open an interactive shell
swift run ssh-client user@example.com

# Execute a remote command
swift run ssh-client user@example.com "cat /etc/os-release"

# Establish local port forwarding
swift run ssh-client -L 8080:localhost:80 user@example.com "sleep 3600"
```
