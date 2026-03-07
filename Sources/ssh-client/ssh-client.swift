//
//  ssh-client.swift
//
//  Copyright 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import ArgumentParser
import SSHClient

/// Command-line entry point for the SSH client executable.
///
/// `SSHClientCommand` defines the public command-line interface exposed by the
/// `ssh-client` binary. It collects the destination, optional forwarding rules,
/// authentication inputs, and any remote command so the executable can either
/// start an interactive shell or execute a single remote request.
@main
struct SSHClientCommand: AsyncParsableCommand {
    /// Static command metadata used by ArgumentParser.
    ///
    /// The configuration sets the executable name that appears in generated help
    /// output and in parser diagnostics.
    static let configuration = CommandConfiguration(
        commandName: "ssh-client"
    )

    /// Local forwarding rules to start before the SSH session begins.
    @Option(name: [.long, .customShort("L")], help: "Local port forwarding in the format [bind_address:]port:host:hostport")
    var listen: [String] = []

    /// Remote destination in `user@host[:port]` form.
    @Argument(help: "The SSH destination in the format user@host[:port]")
    var destination: String

    /// Remote command to run after connecting.
    @Argument(parsing: .captureForPassthrough, help: "The command to execute on the remote host. Omit to start an interactive shell.")
    var command: [String] = []

    /// Optional password for password-based authentication.
    @Option(name: .shortAndLong, help: "Password for authentication (discouraged on command line)")
    var password: String?

    /// Enable additional diagnostic output from the CLI and library.
    @Flag(name: .shortAndLong, help: "Enable verbose debug logging")
    var debug: Bool = false

    /// Run the command-line client.
    ///
    /// The command starts any requested local forwards first, then either executes a
    /// remote command or opens an interactive shell. In interactive mode it also
    /// manages terminal state and prints the usual connection-closed message when the
    /// remote shell exits.
    ///
    /// - Throws: Any uncaught argument parsing or asynchronous setup error.
    func run() async throws {
        let (host, port, user) = SSHClientConfiguration.parseDestination(destination)
        let config = SSHClientConfiguration(
            host: host,
            port: port,
            username: user,
            password: password,
            debug: debug
        )
        
        let client = SSHClient(configuration: config)
        var forwardingConfigurations: [PortForwardingConfiguration] = []
        forwardingConfigurations.reserveCapacity(listen.count)
        for listenString in listen {
            guard let forwardingConfig = PortForwardingConfiguration.parseListen(listenString) else {
                writeStandardErrorLine("[ssh-client] Invalid listen format: \(listenString)")
                Foundation.exit(255)
            }
            forwardingConfigurations.append(forwardingConfig)
        }

        var forwardingServers: [PortForwardingServer] = []
        forwardingServers.reserveCapacity(forwardingConfigurations.count)
        do {
            for forwardingConfig in forwardingConfigurations {
                let server = try await client.startPortForwarding(forwardingConfig)
                try await server.start().get()
                forwardingServers.append(server)
            }
        } catch {
            writeStandardErrorLine("[ssh-client] Port forwarding error: \(error)")
            Foundation.exit(255)
        }
        defer {
            forwardingServers.forEach { server in
                _ = server.close()
            }
        }
        
        if command.isEmpty {
            let exitStatus: Int32
            do {
                let terminal = LocalTerminalConfiguration.current()
                let terminalMode = try LocalTerminalMode()
                defer { terminalMode.restore() }

                let shellExitStatus = try await client.startInteractiveShell(
                    term: terminal.term,
                    terminalCharacterWidth: terminal.columns,
                    terminalRowHeight: terminal.rows
                )
                writeConnectionClosedLine(host: host)
                exitStatus = Int32(shellExitStatus)
            } catch {
                writeStandardErrorLine("[ssh-client] Interactive shell error: \(error)")
                if debug {
                    writeStandardErrorLine("[ssh-client] Error details: \(String(describing: error))")
                }
                Foundation.exit(255)
            }
            Foundation.exit(exitStatus)
        } else {
            // Command execution mode
            do {
                let result = try await client.executeCommand(command.joined(separator: " "))
                
                // Write output to stdout/stderr
                if !result.output.isEmpty {
                    FileHandle.standardOutput.write(result.output)
                }
                if !result.errorOutput.isEmpty {
                    FileHandle.standardError.write(result.errorOutput)
                }

                Foundation.exit(Int32(result.exitStatus))
            } catch {
                writeStandardErrorLine("[ssh-client] Command execution error: \(error)")
                if debug {
                    writeStandardErrorLine("[ssh-client] Error details: \(String(describing: error))")
                }
                Foundation.exit(255)
            }
        }
    }

}
