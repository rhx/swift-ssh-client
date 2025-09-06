//
//  SimpleExecHandler.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore
import NIOSSH

final class SimpleExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias OutboundIn = Never
    typealias OutboundOut = SSHChannelData

    private let command: String
    private var completePromise: EventLoopPromise<Int>?
    private var execAcknowledged = false
    private var exitStatusDelivered = false

    init(command: String, completePromise: EventLoopPromise<Int>) {
        self.command = command
        self.completePromise = completePromise
    }

    func handlerAdded(context: ChannelHandlerContext) {
        // Ensure we can receive half-closure (EOF) and still wait for exit-status.
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        // Send the exec request as soon as the channel is active
        let execRequest = SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true)
        context.triggerUserOutboundEvent(execRequest, promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)
        switch data.type {
        case .channel:
            if case .byteBuffer(let buffer) = data.data {
                if let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) {
                    FileHandle.standardOutput.write(Data(bytes))
                }
            }
        case .stdErr:
            if case .byteBuffer(let buffer) = data.data {
                if let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) {
                    FileHandle.standardError.write(Data(bytes))
                }
            }
        default:
            break
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is ChannelSuccessEvent:
            // Exec request was accepted by the server.
            execAcknowledged = true

        case is ChannelFailureEvent:
            // Exec request was rejected; close and fail.
            if let promise = completePromise {
                completePromise = nil
                promise.fail(SSHClientError.commandExecFailed)
            }
            context.close(promise: nil)

        case let exit as SSHChannelRequestEvent.ExitStatus:
            exitStatusDelivered = true
            if let promise = completePromise {
                completePromise = nil
                promise.succeed(exit.exitStatus)
            }
            // Server may keep channel open for a moment; we can close our side.
            context.close(promise: nil)

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        // If we never completed, fail the promise to unblock waiters.
        if let promise = completePromise {
            completePromise = nil
            // If exec was never acknowledged or we didn't receive exit status, treat as failure.
            promise.fail(SSHClientError.commandExecFailed)
        }
    }

    // Required for ChannelDuplexHandler conformance
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        // This handler does not write any data outbound by itself
        context.write(data, promise: promise)
    }
}
