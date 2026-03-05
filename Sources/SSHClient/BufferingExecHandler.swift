//
//  BufferingExecHandler.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore
import NIOSSH

/// A handler that executes commands and buffers output for programmatic access
final class BufferingExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias OutboundIn = Never
    typealias OutboundOut = SSHChannelData

    private let command: String
    private var completePromise: EventLoopPromise<Int>?
    private var outputPromise: EventLoopPromise<Data>?
    private var errorOutputPromise: EventLoopPromise<Data>?
    private var execAcknowledged = false
    private var exitStatusDelivered = false
    private var output = Data()
    private var errorOutput = Data()

    init(
        command: String,
        completePromise: EventLoopPromise<Int>,
        outputPromise: EventLoopPromise<Data>,
        errorOutputPromise: EventLoopPromise<Data>
    ) {
        self.command = command
        self.completePromise = completePromise
        self.outputPromise = outputPromise
        self.errorOutputPromise = errorOutputPromise
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
                    output.append(Data(bytes))
                }
            }
        case .stdErr:
            if case .byteBuffer(let buffer) = data.data {
                if let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) {
                    errorOutput.append(Data(bytes))
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
            completePromises(exitStatus: -1, error: SSHClientError.commandExecFailed)
            context.close(promise: nil)

        case let exit as SSHChannelRequestEvent.ExitStatus:
            exitStatusDelivered = true
            completePromises(exitStatus: exit.exitStatus, error: nil)
            // Server may keep channel open for a moment; we can close our side.
            context.close(promise: nil)

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        // If we never completed, fail the promise to unblock waiters.
        if completePromise != nil {
            completePromises(exitStatus: -1, error: SSHClientError.commandExecFailed)
        }
    }
    
    private func completePromises(exitStatus: Int, error: Error?) {
        if let promise = completePromise {
            completePromise = nil
            if let error = error {
                promise.fail(error)
            } else {
                promise.succeed(exitStatus)
            }
        }
        
        if let promise = outputPromise {
            outputPromise = nil
            promise.succeed(output)
        }
        
        if let promise = errorOutputPromise {
            errorOutputPromise = nil
            promise.succeed(errorOutput)
        }
    }

    // Required for ChannelDuplexHandler conformance
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        // This handler does not write any data outbound by itself
        context.write(data, promise: promise)
    }
}
