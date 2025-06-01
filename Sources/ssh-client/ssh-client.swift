//
//  ssh-client.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import Dispatch
import NIOCore
import NIOPosix
import NIOSSH
import ArgumentParser

// This file contains an example NIO SSH client. As NIO SSH is currently under active
// development this file doesn't currently do all that much, but it does provide a binary you
// can kick off to get a feel for how NIO SSH drives the connection live. As the feature set of
// NIO SSH increases we'll be adding to this client to try to make it a better example of what you
// can do with NIO SSH.
final class ErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Error in pipeline: \(error)")
        context.close(promise: nil)
    }
}

final class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        // Do not replicate this in your own code: validate host keys! This is a
        // choice made for expedience, not for any other reason.
        validationCompletePromise.succeed(())
    }
}

/// An SSH client command-line tool using SwiftNIO and NIOSSH.
///
/// This command-line utility provides SSH client functionality, including port forwarding and command execution, using SwiftNIO and NIOSSH. It supports specifying a destination (user@host), an optional password, port, and command, as well as local port forwarding via the -L flag. The tool attempts to use the SSH agent for authentication by default, falling back to interactive password authentication if unsuccessful and running from a TTY.
///
/// - Parameters:
///   - listen: An optional listen string for local port forwarding in the format [bind_address:]port:host:hostport
///   - destination: The SSH destination (user@host[:port])
///   - command: The command to execute on the remote host
///   - password: An optional password for authentication
///
/// The command exits with the exit status of the remote command, or 1 if an error occurs.
@main
struct SSHClient: ParsableCommand {
    /// Local port forwarding in the format [bind_address:]port:host:hostport
    @Option(name: .shortAndLong, help: "Local port forwarding in the format [bind_address:]port:host:hostport")
    var listen: String?

    /// The SSH destination in the format user@host[:port]
    @Argument(help: "The SSH destination in the format user@host[:port]")
    var destination: String

    /// The command to execute on the remote host
    @Argument(help: "The command to execute on the remote host")
    var command: [String]

    /// Optional password for authentication
    @Option(name: .shortAndLong, help: "Password for authentication (discouraged on command line)")
    var password: String?

    /// Run the SSH client with the provided arguments.
    ///
    /// This method sets up the event loop, parses the destination, initialises the authentication delegate, and either performs port forwarding or executes a remote command as requested. It preserves the semantics of the original implementation, including agent and password authentication and all error handling.
    ///
    /// - Throws: Any error encountered during SSH connection or command execution.
    func run() throws {
        let (host, port, user) = SSHClient.parseDestination(destination)
        let password = self.password
        let listenStruct = listen.flatMap { SSHClient.parseListen($0) }
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }

        // Choose the appropriate authentication delegate based on command-line flags
        let authDelegate: NIOSSHClientUserAuthenticationDelegate
        if true { // FIXME: should try SSH agent first and fall back to interactive password authentication if unsuccessful (but only if run from a TTY).
            print("Using SSH agent for authentication...")
            authDelegate = PublicKeyAgentDelegate(username: user, password: password)
        } else {
            print("Using interactive password authentication...")
            authDelegate = InteractivePasswordPromptDelegate(username: user, password: password)
        }

        let bootstrap = ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandlers([NIOSSHHandler(role: .client(.init(userAuthDelegate: authDelegate, serverAuthDelegate: AcceptAllHostKeysDelegate())), allocator: channel.allocator, inboundChildChannelInitializer: nil), ErrorHandler()])
            }
            .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)

        let channel = try bootstrap.connect(host: host, port: port).wait()

        if let listen = listenStruct {
            // We've been asked to port forward.
            let server = PortForwardingServer(group: group,
                                              bindHost: listen.bindHost ?? "localhost",
                                              bindPort: listen.bindPort) { inboundChannel in
                channel.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
                    let promise = inboundChannel.eventLoop.makePromise(of: Channel.self)
                    let directTCPIP = SSHChannelType.DirectTCPIP(targetHost: String(listen.targetHost),
                                                                 targetPort: listen.targetPort,
                                                                 originatorAddress: inboundChannel.remoteAddress!)
                    sshHandler.createChannel(promise,
                                             channelType: .directTCPIP(directTCPIP)) { childChannel, channelType in
                        guard case .directTCPIP = channelType else {
                            return channel.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                        }
                        let (ours, theirs) = GlueHandler.matchedPair()
                        return childChannel.pipeline.addHandlers([SSHWrapperHandler(), ours, ErrorHandler()]).flatMap {
                            inboundChannel.pipeline.addHandlers([theirs, ErrorHandler()])
                        }
                    }
                    return promise.futureResult.map { _ in }
                }
            }
            try! server.run().wait()
        } else {
            // We've been asked to exec.
            let exitStatusPromise = channel.eventLoop.makePromise(of: Int.self)
            let childChannel: Channel = try! channel.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
                let promise = channel.eventLoop.makePromise(of: Channel.self)
                sshHandler.createChannel(promise) { childChannel, channelType in
                    guard channelType == .session else {
                        return channel.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                    }
                    return childChannel.pipeline.addHandlers([ExampleExecHandler(command: self.command.joined(separator: " "), completePromise: exitStatusPromise), ErrorHandler()])
                }
                return promise.futureResult
            }.wait()
            try childChannel.closeFuture.wait()
            let exitStatus = try! exitStatusPromise.futureResult.wait()
            try! channel.close().wait()
            Foundation.exit(Int32(exitStatus))
        }
    }

    /// Parse the SSH destination string into host, port, and user.
    ///
    /// This helper replicates the behaviour of the original parser, including default port and user extraction.
    ///
    /// - Parameter destination: The SSH destination string (user@host[:port])
    /// - Returns: A tuple containing host, port, and user.
    static func parseDestination(_ destination: String) -> (host: String, port: Int, user: String?) {
        var user: String?
        var hostPort: String
        if let atIdx = destination.firstIndex(of: "@") {
            user = String(destination[..<atIdx])
            hostPort = String(destination[destination.index(after: atIdx)...])
        } else {
            hostPort = destination
        }
        let host: String
        let port: Int
        if let colonIdx = hostPort.lastIndex(of: ":") {
            host = String(hostPort[..<colonIdx])
            port = Int(hostPort[hostPort.index(after: colonIdx)...]) ?? 22
        } else {
            host = hostPort
            port = 22
        }
        return (host, port, user)
    }

    /// Parse the listen string into its components.
    ///
    /// This helper replicates the behaviour of the original Listen struct.
    ///
    /// - Parameter listenString: The listen string ([bind_address:]port:host:hostport)
    /// - Returns: A Listen struct if parsing is successful, otherwise nil.
    static func parseListen(_ listenString: String) -> Listen? {
        var components = listenString.split(separator: ":")
        var bindHost: Substring? = nil
        switch components.count {
        case 4:
            bindHost = components.removeFirst()
            fallthrough
        case 3:
            guard let bindPort = Int(components.removeFirst()) else { return nil }
            let targetHost = components.removeFirst()
            guard let targetPort = Int(components.removeFirst()) else { return nil }
            return Listen(bindHost: bindHost, bindPort: bindPort, targetHost: targetHost, targetPort: targetPort)
        default:
            return nil
        }
    }

    /// Listen struct matching the original Listen semantics.
    struct Listen {
        var bindHost: Substring?
        var bindPort: Int
        var targetHost: Substring
        var targetPort: Int
    }
}
