//
//  SSHClient.swift
//
//  Copyright 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore
import NIOPosix
import NIOSSH
import SSHAgent

/// Connection settings used to create an `SSHClient`.
///
/// `SSHClientConfiguration` groups the network endpoint, user name, optional
/// password, and debug flag needed to establish an SSH client connection. The
/// value is sendable so callers can prepare configuration on one concurrency
/// domain and hand it to the client actor on another.
public struct SSHClientConfiguration: Sendable {
    /// Host name or address of the remote SSH server.
    public let host: String

    /// TCP port used for the remote SSH server.
    public let port: Int

    /// User name to present during authentication.
    public let username: String

    /// Password to use for password-based authentication, if enabled.
    public let password: String?

    /// Whether to emit debug logging during client setup and session handling.
    public let debug: Bool

    /// Create a complete set of SSH client connection settings.
    ///
    /// The initialiser keeps the most common SSH defaults, including port `22`
    /// and disabled password authentication unless a password is provided.
    ///
    /// - Parameters:
    ///   - host: Host name or address of the remote SSH server.
    ///   - port: TCP port used for the remote SSH server.
    ///   - username: User name to present during authentication.
    ///   - password: Password to use for password-based authentication.
    ///   - debug: Whether to emit debug logging.
    public init(host: String, port: Int = 22, username: String, password: String? = nil, debug: Bool = false) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.debug = debug
    }
    
    /// Parse a destination string in `user@host[:port]` form.
    ///
    /// The parser accepts the same condensed destination style commonly used by
    /// command-line SSH clients. When the user name is omitted, it falls back to
    /// `defaultUsername` or the current local account name.
    ///
    /// - Parameters:
    ///   - destination: Destination string to parse.
    ///   - defaultUsername: Optional fallback user name.
    /// - Returns: Host, port, and user name extracted from the destination.
    public static func parseDestination(_ destination: String, defaultUsername: String? = nil) -> (host: String, port: Int, username: String) {
        let username: String
        let hostPort: String
        if let atIdx = destination.firstIndex(of: "@") {
            username = String(destination[..<atIdx])
            hostPort = String(destination[destination.index(after: atIdx)...])
        } else {
            username = defaultUsername ?? NSUserName()
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
        return (host, port, username)
    }
}

/// Local forwarding settings used to bind a listener and open a direct TCP/IP channel.
///
/// `PortForwardingConfiguration` describes the local address to bind and the
/// remote host and port that should receive forwarded traffic once the SSH
/// session opens the corresponding direct TCP/IP channel.
public struct PortForwardingConfiguration: Sendable {
    /// Local host name or address to bind for the forwarding listener.
    public let bindHost: String

    /// Local TCP port to bind for the forwarding listener.
    public let bindPort: Int

    /// Remote host that should receive forwarded traffic.
    public let targetHost: String

    /// Remote TCP port that should receive forwarded traffic.
    public let targetPort: Int

    /// Create a local forwarding configuration.
    ///
    /// The initialiser defaults the bind host to `localhost`, matching the
    /// conventional SSH behaviour for local-only forwards.
    ///
    /// - Parameters:
    ///   - bindHost: Local host name or address to bind.
    ///   - bindPort: Local TCP port to bind.
    ///   - targetHost: Remote host that should receive forwarded traffic.
    ///   - targetPort: Remote TCP port that should receive forwarded traffic.
    public init(bindHost: String = "localhost", bindPort: Int, targetHost: String, targetPort: Int) {
        self.bindHost = bindHost
        self.bindPort = bindPort
        self.targetHost = targetHost
        self.targetPort = targetPort
    }
    
    /// Parse a forwarding rule in `[bind_address:]port:host:hostport` form.
    ///
    /// The parser mirrors the `-L` syntax used by `ssh`. It accepts either the
    /// short three-field form or the explicit four-field form with a bind host.
    ///
    /// - Parameter listenString: Forwarding rule to parse.
    /// - Returns: Parsed forwarding settings, or `nil` if the rule is invalid.
    public static func parseListen(_ listenString: String) -> PortForwardingConfiguration? {
        var components = listenString.split(separator: ":")
        var bindHost: Substring = "localhost"
        switch components.count {
        case 4:
            bindHost = components.removeFirst()
            fallthrough
        case 3:
            guard let bindPort = Int(components.removeFirst()) else { return nil }
            let targetHost = components.removeFirst()
            guard let targetPort = Int(components.removeFirst()) else { return nil }
            return PortForwardingConfiguration(
                bindHost: String(bindHost),
                bindPort: bindPort,
                targetHost: String(targetHost),
                targetPort: targetPort
            )
        default:
            return nil
        }
    }
}

/// Output captured from a completed remote command.
///
/// `CommandResult` preserves the remote exit status together with the bytes read
/// from standard output and standard error. Callers can decode those payloads in
/// whatever text or binary form is appropriate for the command they ran.
public struct CommandResult: Sendable {
    /// Exit status reported by the remote command.
    public let exitStatus: Int

    /// Bytes received on the remote standard output stream.
    public let output: Data

    /// Bytes received on the remote standard error stream.
    public let errorOutput: Data

    /// Create a command result from captured remote process state.
    ///
    /// - Parameters:
    ///   - exitStatus: Exit status reported by the remote command.
    ///   - output: Bytes received on standard output.
    ///   - errorOutput: Bytes received on standard error.
    public init(exitStatus: Int, output: Data = Data(), errorOutput: Data = Data()) {
        self.exitStatus = exitStatus
        self.output = output
        self.errorOutput = errorOutput
    }
}

/// Actor that manages SSH connections, sessions, and local forwards.
///
/// `SSHClient` owns the underlying `SwiftNIO` event loop resources and the root
/// SSH connection channel. It exposes async methods for connecting, running a
/// remote command, starting an interactive shell, and establishing local port
/// forwards without requiring callers to assemble a `NIOSSH` pipeline directly.
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
public actor SSHClient {
    private let configuration: SSHClientConfiguration
    private let eventLoopGroup: EventLoopGroup
    private var connection: Channel?
    private let ownsEventLoopGroup: Bool
    
    /// Create an SSH client for the supplied configuration.
    ///
    /// Callers can either inject an existing event loop group or let the actor
    /// create and own a single-threaded group for its own lifetime.
    ///
    /// - Parameters:
    ///   - configuration: Connection settings for the SSH client.
    ///   - eventLoopGroup: Optional event loop group to reuse.
    public init(configuration: SSHClientConfiguration, eventLoopGroup: EventLoopGroup? = nil) {
        self.configuration = configuration
        if let eventLoopGroup = eventLoopGroup {
            self.eventLoopGroup = eventLoopGroup
            self.ownsEventLoopGroup = false
        } else {
            self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            self.ownsEventLoopGroup = true
        }
    }
    
    deinit {
        if ownsEventLoopGroup {
            try? eventLoopGroup.syncShutdownGracefully()
        }
    }
    
    /// Establish the underlying SSH connection if one is not already open.
    ///
    /// The method configures authentication delegates, builds the root `NIOSSH`
    /// pipeline, and connects the client bootstrap to the configured host and
    /// port. Repeated calls are harmless once the connection is active.
    ///
    /// - Throws: `SSHClientError` or transport errors if the connection fails.
    public func connect() async throws {
        guard connection == nil else { return } // Already connected
        
        // Configure SSHAgent debug
        await SSHAgent.shared.setDebug(configuration.debug)
        
        // Create authentication delegate
        let authDelegate: NIOSSHClientUserAuthenticationDelegate = CompositeAuthDelegate(
            username: configuration.username,
            password: configuration.password,
            debug: configuration.debug
        )
        
        let bootstrap = ClientBootstrap(group: eventLoopGroup)
            .channelInitializer { channel in
                if self.configuration.debug { print("[debug] root channel initializer") }
                let sshHandler = NIOSSHHandler(
                    role: .client(.init(userAuthDelegate: authDelegate, serverAuthDelegate: AcceptAllHostKeysDelegate())),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: nil
                )
                return channel.pipeline.addHandler(sshHandler).flatMap {
                    channel.pipeline.addHandler(ErrorHandler())
                }
            }
            .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
        
        connection = try await bootstrap.connect(host: configuration.host, port: configuration.port).get()
    }
    
    /// Execute a non-interactive command on the remote server.
    ///
    /// The client opens a session channel, sends an exec request, buffers stdout
    /// and stderr until the channel finishes draining, and then returns the
    /// collected output together with the remote exit status.
    ///
    /// - Parameter command: Command string to execute remotely.
    /// - Returns: Buffered output and exit status from the remote command.
    /// - Throws: `SSHClientError` or transport errors if execution fails.
    public func executeCommand(_ command: String) async throws -> CommandResult {
        try await connect()
        guard let connection = connection else {
            throw SSHClientError.connectionNotEstablished
        }
        
        let exitStatusPromise = connection.eventLoop.makePromise(of: Int.self)
        let outputPromise = connection.eventLoop.makePromise(of: Data.self)
        let errorOutputPromise = connection.eventLoop.makePromise(of: Data.self)
        
        if configuration.debug { print("[debug] starting SSH session channel creation") }

        let childChannel: EventLoopFuture<Channel> = connection.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
            let promise = connection.eventLoop.makePromise(of: Channel.self)
            if self.configuration.debug { print("[debug] creating session channel") }
            sshHandler.createChannel(promise) { childChannel, channelType in
                guard channelType == .session else {
                    return connection.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                }
                return childChannel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).flatMap {
                    var handlers: [ChannelHandler] = []
                    if self.configuration.debug {
                        handlers.append(SSHChildDebugHandler(label: "exec", verbose: true))
                    }
                    handlers.append(
                        BufferingExecHandler(
                            command: command,
                            completePromise: exitStatusPromise,
                            outputPromise: outputPromise,
                            errorOutputPromise: errorOutputPromise
                        )
                    )
                    handlers.append(ErrorHandler())
                    return childChannel.pipeline.addHandlers(handlers)
                }
            }
            return promise.futureResult
        }

        // Collect the result through a helper that guarantees the three result
        // promises are completed on every exit path (success or failure), so a
        // failed channel creation can never leave a promise unfulfilled and trap
        // NIO's debug `EventLoopPromise.deinit` precondition.
        return try await SSHClient.collectCommandResult(
            channelCreation: childChannel,
            exitStatusPromise: exitStatusPromise,
            outputPromise: outputPromise,
            errorOutputPromise: errorOutputPromise
        ).get()
    }

    /// Awaits channel creation and collects the command result from the supplied
    /// promises, guaranteeing that all three promises are completed on every exit
    /// path (so none leak unfulfilled and trap NIO's debug `deinit` check).
    ///
    /// - Parameters:
    ///   - channelCreation: A future for the session channel.
    ///   - exitStatusPromise: Promise fulfilled with the remote exit status.
    ///   - outputPromise: Promise fulfilled with captured standard output.
    ///   - errorOutputPromise: Promise fulfilled with captured standard error.
    /// - Returns: A future for the assembled ``CommandResult``.
    static func collectCommandResult(
        channelCreation: EventLoopFuture<Channel>,
        exitStatusPromise: EventLoopPromise<Int>,
        outputPromise: EventLoopPromise<Data>,
        errorOutputPromise: EventLoopPromise<Data>
    ) -> EventLoopFuture<CommandResult> {
        // If channel creation (or the wait for completion) fails, the three
        // result promises are never wired to a handler and would otherwise leak
        // unfulfilled, tripping NIO's debug `EventLoopPromise.deinit` precondition
        // and trapping the process. Fail them explicitly on the error path so
        // every promise is completed exactly once.
        channelCreation.flatMap { channel in
            channel.closeFuture.flatMap {
                exitStatusPromise.futureResult.flatMap { exitStatus in
                    outputPromise.futureResult.flatMap { output in
                        errorOutputPromise.futureResult.map { errorOutput in
                            CommandResult(exitStatus: exitStatus, output: output, errorOutput: errorOutput)
                        }
                    }
                }
            }
        }.flatMapError { error in
            exitStatusPromise.fail(error)
            outputPromise.fail(error)
            errorOutputPromise.fail(error)
            return channelCreation.eventLoop.makeFailedFuture(error)
        }
    }

    /// Start an interactive remote shell using a pseudo-terminal request.
    ///
    /// The method opens a session channel, requests a pseudo-terminal with the
    /// supplied terminal metadata, and then waits until the remote shell exits.
    /// The returned value is the remote shell's exit status.
    ///
    /// - Parameters:
    ///   - term: Terminal type to request from the remote server.
    ///   - terminalCharacterWidth: Terminal width in character cells.
    ///   - terminalRowHeight: Terminal height in character cells.
    ///   - terminalPixelWidth: Terminal width in pixels, if known.
    ///   - terminalPixelHeight: Terminal height in pixels, if known.
    ///   - terminalModes: Terminal mode flags to send with the request.
    /// - Returns: Exit status reported by the remote shell.
    /// - Throws: `SSHClientError` or transport errors if the shell cannot be started.
    @discardableResult
    public func startInteractiveShell(
        term: String,
        terminalCharacterWidth: Int,
        terminalRowHeight: Int,
        terminalPixelWidth: Int = 0,
        terminalPixelHeight: Int = 0,
        terminalModes: SSHTerminalModes = .init([:])
    ) async throws -> Int {
        try await connect()
        guard let connection = connection else {
            throw SSHClientError.connectionNotEstablished
        }

        let exitStatusPromise = connection.eventLoop.makePromise(of: Int.self)
        let pseudoTerminalRequest = SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true,
            term: term,
            terminalCharacterWidth: terminalCharacterWidth,
            terminalRowHeight: terminalRowHeight,
            terminalPixelWidth: terminalPixelWidth,
            terminalPixelHeight: terminalPixelHeight,
            terminalModes: terminalModes
        )

        let childChannel = try await connection.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
            let promise = connection.eventLoop.makePromise(of: Channel.self)
            sshHandler.createChannel(promise) { childChannel, channelType in
                guard channelType == .session else {
                    return connection.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                }

                return childChannel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).flatMap {
                    childChannel.pipeline.addHandlers([
                        InteractiveShellHandler(
                            pseudoTerminalRequest: pseudoTerminalRequest,
                            completePromise: exitStatusPromise
                        ),
                        ErrorHandler(),
                    ])
                }
            }
            return promise.futureResult
        }.get()

        try await childChannel.closeFuture.get()
        return try await exitStatusPromise.futureResult.get()
    }
    
    /// Start a local forwarding server for the supplied configuration.
    ///
    /// The returned server binds a local listener and, for each inbound local
    /// connection, opens a matching SSH direct TCP/IP channel towards the target
    /// host and port described by the configuration.
    ///
    /// - Parameter config: Forwarding settings for the listener and target.
    /// - Returns: A started forwarding server wrapper.
    /// - Throws: `SSHClientError` or transport errors if setup fails.
    public func startPortForwarding(_ config: PortForwardingConfiguration) async throws -> PortForwardingServer {
        try await connect()
        guard let connection = connection else {
            throw SSHClientError.connectionNotEstablished
        }
        
        let server = PortForwardingServer(
            group: eventLoopGroup,
            bindHost: Substring(config.bindHost),
            bindPort: config.bindPort
        ) { inboundChannel in
            connection.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
                let promise = inboundChannel.eventLoop.makePromise(of: Channel.self)
                let directTCPIP = SSHChannelType.DirectTCPIP(
                    targetHost: config.targetHost,
                    targetPort: config.targetPort,
                    originatorAddress: inboundChannel.remoteAddress!
                )
                sshHandler.createChannel(promise,
                                         channelType: .directTCPIP(directTCPIP)) { childChannel, channelType in
                    guard case .directTCPIP = channelType else {
                        return connection.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                    }
                    let (ours, theirs) = GlueHandler.matchedPair()
                    return childChannel.pipeline.addHandlers([SSHWrapperHandler(), ours, ErrorHandler()]).flatMap {
                        inboundChannel.pipeline.addHandlers([theirs, ErrorHandler()])
                    }
                }
                return promise.futureResult.map { _ in }
            }
        }
        
        return server
    }
    
    /// Close the current SSH connection, if one is active.
    ///
    /// After disconnection, the actor can establish a new connection later by
    /// calling `connect()` again.
    ///
    /// - Throws: Transport errors if the channel close fails.
    public func disconnect() async throws {
        if let connection = connection {
            try await connection.close().get()
            self.connection = nil
        }
    }
    
    /// Whether the underlying SSH connection channel is currently active.
    public var isConnected: Bool {
        connection?.isActive ?? false
    }
}

// MARK: - Error Types

/// Errors raised by the high-level SSH client API.
///
/// `SSHClientError` groups the package's own connection, authentication, and
/// channel-management failures. Lower-level transport and `NIOSSH` errors are
/// still surfaced directly where that gives callers more specific information.
public enum SSHClientError: Error, Sendable {
    case connectionNotEstablished
    case passwordAuthenticationNotSupported
    case publicKeyAuthenticationNotSupported
    case commandExecFailed
    case invalidChannelType
    case invalidData
}
