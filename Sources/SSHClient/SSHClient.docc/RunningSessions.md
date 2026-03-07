# Running Sessions

Open a remote command channel or attach the local terminal to an interactive shell.

## Overview

`SSHClient` uses separate handlers for non-interactive and interactive sessions. `BufferingExecHandler` collects stdout, stderr, and exit status so `executeCommand(_:)` can return a single `CommandResult`. `InteractiveShellHandler` wires the child channel to the local terminal and requests a pseudo-terminal before starting the remote shell.

Both flows use half-closure so the client can continue reading trailing output after the remote side has indicated completion. This matters for commands that send `exit-status` before the final data frame, and for interactive sessions that need stdout and stderr to drain cleanly before the channel closes.

## Topics

### Session APIs

- ``SSHClient/executeCommand(_:)``
- ``SSHClient/startInteractiveShell(term:terminalCharacterWidth:terminalRowHeight:terminalPixelWidth:terminalPixelHeight:terminalModes:)``

