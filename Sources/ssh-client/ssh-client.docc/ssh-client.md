# ``ssh_client``

@Metadata {
    @DisplayName("ssh-client")
}

A command-line SSH client that mirrors the package’s interactive shell, command execution, and local forwarding APIs.

## Overview

The `ssh-client` executable is a thin wrapper over the `SSHClient` library. It parses a destination, optional `-L` forwarding rules, and an optional remote command. If no command is supplied it starts an interactive shell and requests a pseudo-terminal in the same way the library API does.

The command-line target also owns terminal-specific concerns such as writing diagnostic messages to standard error and restoring terminal state when an interactive shell exits. Those concerns live outside the reusable library so that the library can stay platform-focused and suitable for embedding in other Swift programs.

## Topics

### Command Interface

- <doc:UsingTheCommandLineTool>
