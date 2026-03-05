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

/// Configuration for SSH client connections
public struct SSHClientConfiguration: Sendable {
    public let host: String
    public let port: Int
    public let username: String
    public let password: String?
    public let debug: Bool
    
    public init(host: String, port: Int = 22, username: String, password: String? = nil, debug: Bool = false) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.debug = debug
    }
    
    /// Parse destination string in format user@host[:port]
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

/// Configuration for port forwarding
public struct PortForwardingConfiguration: Sendable {
    public let bindHost: String
    public let bindPort: Int
    public let targetHost: String
    public let targetPort: Int
    
    public init(bindHost: String = "localhost", bindPort: Int, targetHost: String, targetPort: Int) {
        self.bindHost = bindHost
        self.bindPort = bindPort
        self.targetHost = targetHost
        self.targetPort = targetPort
    }
    
    /// Parse listen string in format [bind_address:]port:host:hostport
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

/// Result of command execution
public struct CommandResult: Sendable {
    public let exitStatus: Int
    public let output: Data
    public let errorOutput: Data
    
    public init(exitStatus: Int, output: Data = Data(), errorOutput: Data = Data()) {
        self.exitStatus = exitStatus
        self.output = output
        self.errorOutput = errorOutput
    }
}

/// SSH Client actor for managing SSH connections and operations
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
public actor SSHClient {
    private let configuration: SSHClientConfiguration
    private let eventLoopGroup: EventLoopGroup
    private var connection: Channel?
    private let ownsEventLoopGroup: Bool
    
    /// Initialize SSH client with configuration
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
    
    /// Connect to the SSH server
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
    
    /// Execute a command on the remote server
    public func executeCommand(_ command: String) async throws -> CommandResult {
        try await connect()
        guard let connection = connection else {
            throw SSHClientError.connectionNotEstablished
        }
        
        let exitStatusPromise = connection.eventLoop.makePromise(of: Int.self)
        let outputPromise = connection.eventLoop.makePromise(of: Data.self)
        let errorOutputPromise = connection.eventLoop.makePromise(of: Data.self)
        
        if configuration.debug { print("[debug] starting SSH session channel creation") }
        
        let childChannel = try await connection.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
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
        }.get()
        
        // Wait for command completion
        try await childChannel.closeFuture.get()
        let exitStatus = try await exitStatusPromise.futureResult.get()
        let output = try await outputPromise.futureResult.get()
        let errorOutput = try await errorOutputPromise.futureResult.get()
        
        return CommandResult(exitStatus: exitStatus, output: output, errorOutput: errorOutput)
    }
    
    /// Start port forwarding
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
    
    /// Disconnect from the SSH server
    public func disconnect() async throws {
        if let connection = connection {
            try await connection.close().get()
            self.connection = nil
        }
    }
    
    /// Check if connected to the server
    public var isConnected: Bool {
        connection?.isActive ?? false
    }
}

// MARK: - Error Types

public enum SSHClientError: Error, Sendable {
    case connectionNotEstablished
    case passwordAuthenticationNotSupported
    case publicKeyAuthenticationNotSupported
    case commandExecFailed
    case invalidChannelType
    case invalidData
}
