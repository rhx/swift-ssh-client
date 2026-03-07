# Using the Command-Line Tool

Run commands, open shells, and attach local forwards from the terminal.

## Overview

`ssh-client` accepts the destination in `user@host[:port]` form, followed by an optional remote command. When the command is omitted, the tool opens an interactive shell and restores the local terminal when the remote shell exits.

Local port forwarding is supplied with one or more `-L` options in `[bind_address:]port:host:hostport` form. The tool starts each listener before opening the session so forwarding can accompany either a remote command or an interactive shell.

## Examples

Open an interactive shell:

```bash
ssh-client user@example.com
```

Run a command:

```bash
ssh-client user@example.com uname -a
```

Run multiple forwards and then open a shell:

```bash
ssh-client -L 8080:web.internal:80 -L 5432:db.internal:5432 user@example.com
```
