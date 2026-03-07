//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import NIOCore
import NIOConcurrencyHelpers
import NIOPosix
import NIOSSH

public final class PortForwardingServer: Sendable {
    private let serverChannel: NIOLockedValueBox<Channel?>
    private let serverLoop: EventLoop
    private let group: EventLoopGroup
    private let bindHost: Substring
    private let bindPort: Int
    private let forwardingChannelConstructor: @Sendable (Channel) -> EventLoopFuture<Void>

    @preconcurrency
    public init(
        group: EventLoopGroup,
        bindHost: Substring,
        bindPort: Int,
        _ forwardingChannelConstructor: @escaping @Sendable (Channel) -> EventLoopFuture<Void>
    ) {
        self.serverLoop = group.next()
        self.serverChannel = NIOLockedValueBox(nil)
        self.group = group
        self.forwardingChannelConstructor = forwardingChannelConstructor
        self.bindHost = bindHost
        self.bindPort = bindPort
    }

    public func start() -> EventLoopFuture<Void> {
        ServerBootstrap(group: self.serverLoop, childGroup: self.group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer(self.forwardingChannelConstructor)
            .bind(host: String(self.bindHost), port: self.bindPort).map { channel in
                self.serverChannel.withLockedValue { storedChannel in
                    storedChannel = channel
                }
            }
    }

    public func run() -> EventLoopFuture<Void> {
        self.start().flatMap {
            self.serverLoop.flatSubmit {
                guard let server = self.serverChannel.withLockedValue({ $0 }) else {
                    return self.serverLoop.makeFailedFuture(SSHClientError.connectionNotEstablished)
                }

                return server.closeFuture
            }
        }
    }

    public func close() -> EventLoopFuture<Void> {
        self.serverLoop.flatSubmit {
            guard let server = self.serverChannel.withLockedValue({ $0 }) else {
                // The server wasn't created yet, so we can just shut down straight away and let
                // the OS clean us up.
                return self.serverLoop.makeSucceededFuture(())
            }

            return server.close()
        }
    }
}

/// Channel handler that wraps forwarded bytes in `SSHChannelData`.
///
/// `SSHWrapperHandler` adapts raw `ByteBuffer` traffic from the local forwarding
/// side into the SSH channel payloads expected by `NIOSSH`, and performs the
/// inverse conversion for inbound data.
public final class SSHWrapperHandler: ChannelDuplexHandler, @unchecked Sendable {
    public typealias InboundIn = SSHChannelData
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = SSHChannelData

    public init() {}

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .channel = data.type, case .byteBuffer(let buffer) = data.data else {
            context.fireErrorCaught(SSHClientError.invalidData)
            return
        }

        context.fireChannelRead(self.wrapInboundOut(buffer))
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        let wrapped = SSHChannelData(type: .channel, data: .byteBuffer(data))
        context.write(self.wrapOutboundOut(wrapped), promise: promise)
    }
}

// MARK: - GlueHandler

public final class GlueHandler: @unchecked Sendable {
    private var partner: GlueHandler?
    private var context: ChannelHandlerContext?
    private var pendingRead: Bool = false

    private init() {}
}

extension GlueHandler {
    public static func matchedPair() -> (GlueHandler, GlueHandler) {
        let first = GlueHandler()
        let second = GlueHandler()

        first.partner = second
        second.partner = first

        return (first, second)
    }
}

extension GlueHandler {
    private func partnerWrite(_ data: NIOAny) {
        self.context?.write(data, promise: nil)
    }

    private func partnerFlush() {
        self.context?.flush()
    }

    private func partnerWriteEOF() {
        self.context?.close(mode: .output, promise: nil)
    }

    private func partnerCloseFull() {
        self.context?.close(promise: nil)
    }

    private func partnerBecameWritable() {
        if self.pendingRead {
            self.pendingRead = false
            self.context?.read()
        }
    }

    private var partnerWritable: Bool {
        self.context?.channel.isWritable ?? false
    }
}

extension GlueHandler: ChannelDuplexHandler {
    public typealias InboundIn = NIOAny
    public typealias OutboundIn = NIOAny
    public typealias OutboundOut = NIOAny

    public func handlerAdded(context: ChannelHandlerContext) {
        self.context = context

        // It's possible our partner asked if we were writable, before, and we couldn't answer.
        // Consider updating it.
        if context.channel.isWritable {
            self.partner?.partnerBecameWritable()
        }
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
        self.partner = nil
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self.partner?.partnerWrite(data)
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        self.partner?.partnerFlush()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        self.partner?.partnerCloseFull()
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? ChannelEvent, case .inputClosed = event {
            // We have read EOF.
            self.partner?.partnerWriteEOF()
        }
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.partner?.partnerCloseFull()
    }

    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable {
            self.partner?.partnerBecameWritable()
        }
    }

    public func read(context: ChannelHandlerContext) {
        if let partner = self.partner, partner.partnerWritable {
            context.read()
        } else {
            self.pendingRead = true
        }
    }
}
