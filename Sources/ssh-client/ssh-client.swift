//
//  ssh-client.swift
//
//  Copyright 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import ArgumentParser
import SSHClient

/// An SSH client command-line tool using SwiftNIO and NIOSSH.
@main
struct SSHClientCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ssh-client"
    )
    @Option(name: .shortAndLong, help: "Local port forwarding in the format [bind_address:]port:host:hostport")
    var listen: String?

    @Argument(help: "The SSH destination in the format user@host[:port]")
    var destination: String

    @Argument(help: "The command to execute on the remote host")
    var command: [String]

    @Option(name: .shortAndLong, help: "Password for authentication (discouraged on command line)")
    var password: String?

    @Flag(name: .shortAndLong, help: "Enable verbose debug logging")
    var debug: Bool = false

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
        
        if let listenString = listen {
            // Port forwarding mode
            guard let forwardingConfig = PortForwardingConfiguration.parseListen(listenString) else {
                fputs("[ssh-client] Invalid listen format: \(listenString)\n", stderr)
                Foundation.exit(255)
            }
            
            do {
                let server = try await client.startPortForwarding(forwardingConfig)
                try await server.run().get()
            } catch {
                fputs("[ssh-client] Port forwarding error: \(error)\n", stderr)
                Foundation.exit(255)
            }
        } else {
            // Command execution mode
            guard !command.isEmpty else {
                fputs("[ssh-client] No command provided\n", stderr)
                Foundation.exit(255)
            }
            
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
                fputs("[ssh-client] Command execution error: \(error)\n", stderr)
                if debug {
                    fputs("[ssh-client] Error details: \(String(describing: error))\n", stderr)
                }
                Foundation.exit(255)
            }
        }
    }

}
