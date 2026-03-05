//
//  SSHAgentResponseHandler.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore

/// Channel handler for reading SSH agent responses.
///
/// This handler is used to capture responses from SSH agent requests in a
/// synchronous manner. It reads the length-prefixed response format used
/// by the SSH agent protocol and delivers the complete response through
/// a promise.
final class SSHAgentResponseHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let promise: EventLoopPromise<Data?>
    private let debug: Bool
    private var expectedLength: UInt32?
    private var responseBuffer: ByteBuffer?

    init(promise: EventLoopPromise<Data?>, debug: Bool = false) {
        self.promise = promise
        self.debug = debug
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)

        // If we don't have the length yet, try to read it
        if expectedLength == nil {
            guard buffer.readableBytes >= 4 else {
                // Not enough data yet, wait for more
                return
            }

            expectedLength = buffer.readInteger(endianness: .big, as: UInt32.self)
            if debug {
                print("[SSHAgent] Expecting response of \(expectedLength ?? 0) bytes")
            }
        }

        guard let length = expectedLength else { return }

        // Initialize response buffer if needed
        if responseBuffer == nil {
            responseBuffer = context.channel.allocator.buffer(capacity: Int(length))
        }

        // Read as much data as we can
        let availableBytes = buffer.readableBytes
        let neededBytes = Int(length) - (responseBuffer?.readableBytes ?? 0)
        let bytesToRead = min(availableBytes, neededBytes)

        if let bytes = buffer.readBytes(length: bytesToRead) {
            responseBuffer?.writeBytes(bytes)
        }

        // Check if we have the complete response
        if let responseBuffer = responseBuffer, responseBuffer.readableBytes >= length {
            if let responseData = responseBuffer.getBytes(at: responseBuffer.readerIndex, length: Int(length)) {
                let data = Data(responseData)
                if debug {
                    print("[SSHAgent] Received complete response of \(data.count) bytes")
                }
                promise.succeed(data)
            } else {
                promise.succeed(nil)
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if debug {
            print("[SSHAgent] Channel error: \(error)")
        }
        promise.succeed(nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if debug {
            print("[SSHAgent] Channel became inactive")
        }
        promise.succeed(nil)
    }
}
