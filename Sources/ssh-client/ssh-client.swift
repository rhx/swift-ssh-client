//
//  ssh-client.swift
//
//  Copyright 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import Dispatch
import NIOCore
import NIOPosix
import NIOSSH
import ArgumentParser
import SSHAgent

final class ErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Do not print here; the command will print conditionally when --debug is set.
        context.close(promise: nil)
    }
}

final class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        validationCompletePromise.succeed(())
    }
}

// Debug handler for SSH child channels.
final class SSHChildDebugHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData

    private let label: String
    private let verbose: Bool

    init(label: String, verbose: Bool) {
        self.label = label
        self.verbose = verbose
    }

    func handlerAdded(context: ChannelHandlerContext) {
        if verbose { print("[debug:\(label)] handlerAdded") }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        if verbose { print("[debug:\(label)] handlerRemoved") }
    }

    func channelActive(context: ChannelHandlerContext) {
        if verbose { print("[debug:\(label)] channelActive") }
        context.fireChannelActive()
    }

    func channelInactive(context: ChannelHandlerContext) {
        if verbose { print("[debug:\(label)] channelInactive") }
        context.fireChannelInactive()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if verbose {
            switch event {
            case is ChannelSuccessEvent:
                print("[debug:\(label)] userInboundEvent: ChannelSuccessEvent")
            case is ChannelFailureEvent:
                print("[debug:\(label)] userInboundEvent: ChannelFailureEvent")
            case let exit as SSHChannelRequestEvent.ExitStatus:
                print("[debug:\(label)] userInboundEvent: ExitStatus(\(exit.exitStatus))")
            default:
                print("[debug:\(label)] userInboundEvent: \(type(of: event))")
            }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let msg = self.unwrapInboundIn(data)
        if verbose {
            switch msg.type {
            case .channel:
                if case .byteBuffer(let buf) = msg.data {
                    print("[debug:\(label)] channelRead stdout \(buf.readableBytes) bytes")
                } else {
                    print("[debug:\(label)] channelRead stdout non-buffer")
                }
            case .stdErr:
                if case .byteBuffer(let buf) = msg.data {
                    print("[debug:\(label)] channelRead stderr \(buf.readableBytes) bytes")
                } else {
                    print("[debug:\(label)] channelRead stderr non-buffer")
                }
            default:
                print("[debug:\(label)] channelRead other type \(msg.type)")
            }
        }
        context.fireChannelRead(data)
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        if verbose { print("[debug:\(label)] write") }
        context.write(data, promise: promise)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if verbose { print("[debug:\(label)] errorCaught: \(error)") }
        context.fireErrorCaught(error)
    }
}

/// An SSH client command-line tool using SwiftNIO and NIOSSH.
@main
struct SSHClient: ParsableCommand {
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

    func run() throws {
        let (host, port, user) = SSHClient.parseDestination(destination)
        let password = self.password
        let listenStruct = listen.flatMap { SSHClient.parseListen($0) }
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }

        // Configure SSHAgent global debug
        Task {
            await SSHAgent.shared.setDebug(self.debug)
        }

        // Use composite authentication strategy: try SSH agent first, fall back to password
        let authDelegate: NIOSSHClientUserAuthenticationDelegate = CompositeAuthDelegate(
            username: user,
            password: password,
            debug: self.debug
        )

        let bootstrap = ClientBootstrap(group: group)
            .channelInitializer { channel in
                if self.debug { print("[debug] root channel initializer") }
                // Add handlers sequentially to avoid Sendable inference on arrays (Swift 6).
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

        let channel: Channel
        do {
            channel = try bootstrap.connect(host: host, port: port).wait()
        } catch {
            fputs("[ssh-client] Connect error: \(error)\n", stderr)
            Foundation.exit(255)
        }

        if let listen = listenStruct {
            let server = PortForwardingServer(group: group,
                                              bindHost: listen.bindHost ?? "localhost",
                                              bindPort: listen.bindPort) { inboundChannel in
                channel.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
                    let promise = inboundChannel.eventLoop.makePromise(of: Channel.self)
                    let directTCPIP = SSHChannelType.DirectTCPIP(
                        targetHost: String(listen.targetHost),
                        targetPort: listen.targetPort,
                        originatorAddress: inboundChannel.remoteAddress!
                    )
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
            do {
                try server.run().wait()
            } catch {
                fputs("[ssh-client] Server error: \(error)\n", stderr)
                Foundation.exit(255)
            }
        } else {
            let exitStatusPromise = channel.eventLoop.makePromise(of: Int.self)
            if self.debug { print("[debug] starting SSH session channel creation") }
            let childChannel: Channel
            do {
                if self.debug { print("[debug] getting SSH handler from pipeline") }
                childChannel = try channel.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
                    let promise = channel.eventLoop.makePromise(of: Channel.self)
                    if self.debug { print("[debug] creating session channel") }
                    sshHandler.createChannel(promise) { childChannel, channelType in
                        guard channelType == .session else {
                            return channel.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                        }
                        // Allow remote half-closure
                        return childChannel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).flatMap {
                            var handlers: [ChannelHandler] = []
                            if self.debug {
                                handlers.append(SSHChildDebugHandler(label: "exec", verbose: true))
                            }
                            handlers.append(SimpleExecHandler(command: self.command.joined(separator: " "), completePromise: exitStatusPromise))
                            handlers.append(ErrorHandler())
                            return childChannel.pipeline.addHandlers(handlers)
                        }
                    }
                    return promise.futureResult
                }.wait()
            } catch {
                fputs("[ssh-client] Channel creation error: \(error)\n", stderr)
                if self.debug {
                    fputs("[ssh-client] Channel creation error details: \(String(describing: error))\n", stderr)
                }
                Foundation.exit(255)
            }

            do {
                try childChannel.closeFuture.wait()
            } catch {
                if self.debug { print("[ssh-client] Channel close error: \(error)") }
                Foundation.exit(255)
            }

            let exitStatus: Int
            do {
                exitStatus = try exitStatusPromise.futureResult.wait()
            } catch {
                fputs("[ssh-client] Command execution error: \(error)\n", stderr)
                Foundation.exit(255)
            }
            do {
                try channel.close().wait()
            } catch {
                if self.debug { print("[ssh-client] Connection close error: \(error)") }
                Foundation.exit(255)
            }
            Foundation.exit(Int32(exitStatus))
        }
    }

    static func parseDestination(_ destination: String) -> (host: String, port: Int, user: String) {
        let user: String
        let hostPort: String
        if let atIdx = destination.firstIndex(of: "@") {
            user = String(destination[..<atIdx])
            hostPort = String(destination[destination.index(after: atIdx)...])
        } else {
            user = NSUserName()
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

    struct Listen {
        var bindHost: Substring?
        var bindPort: Int
        var targetHost: Substring
        var targetPort: Int
    }
}

