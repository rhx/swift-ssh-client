//
//  BufferingExecHandler.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore
import NIOSSH

/// Execute a remote command and buffer its output for later collection.
///
/// `SSHClient.executeCommand(_:)` uses this handler to request command execution on
/// a session channel and then accumulate stdout, stderr, and exit status until the
/// channel becomes inactive.
final class BufferingExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias OutboundIn = Never
    typealias OutboundOut = SSHChannelData

    /// Command string sent in the exec request.
    private let command: String

    /// Promise resolved with the remote exit status.
    private var completePromise: EventLoopPromise<Int>?

    /// Promise resolved with buffered stdout data.
    private var outputPromise: EventLoopPromise<Data>?

    /// Promise resolved with buffered stderr data.
    private var errorOutputPromise: EventLoopPromise<Data>?

    /// Flag indicating whether the remote side acknowledged the exec request.
    private var execAcknowledged = false

    /// Exit status reported by the remote side.
    private var exitStatus: Int?

    /// Buffered stdout data received so far.
    private var output = Data()

    /// Buffered stderr data received so far.
    private var errorOutput = Data()

    /// Create the handler and its completion promises.
    ///
    /// The handler keeps separate promises for the remote exit status, standard
    /// output, and standard error so `SSHClient.executeCommand(_:)` can await all
    /// three results after the channel finishes draining.
    ///
    /// - Parameters:
    ///   - command: The remote command to execute.
    ///   - completePromise: The promise completed with the exit status.
    ///   - outputPromise: The promise completed with buffered stdout data.
    ///   - errorOutputPromise: The promise completed with buffered stderr data.
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

    /// Enable remote half-closure so the handler can receive late output.
    ///
    /// Some servers send `exit-status` before the final output frame. Allowing
    /// remote half-closure lets the handler continue reading until the channel
    /// actually becomes inactive.
    ///
    /// - Parameter context: The current channel handler context.
    func handlerAdded(context: ChannelHandlerContext) {
        // Ensure we can receive half-closure (EOF) and still wait for exit-status.
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    /// Send the exec request when the session channel becomes active.
    ///
    /// The handler sends the request immediately after activation so the session
    /// channel enters command-execution mode before any other channel traffic is
    /// exchanged.
    ///
    /// - Parameter context: The current channel handler context.
    func channelActive(context: ChannelHandlerContext) {
        // Send the exec request as soon as the channel is active
        let execRequest = SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true)
        context.triggerUserOutboundEvent(execRequest, promise: nil)
    }

    /// Buffer stdout and stderr messages from the remote command.
    ///
    /// The SSH session delivers standard output and standard error as separate
    /// channel data streams. This handler preserves that separation whilst
    /// accumulating the complete payload for the caller.
    ///
    /// - Parameters:
    ///   - context: The current channel handler context.
    ///   - data: The inbound SSH channel data.
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

    /// Process command acknowledgement and exit-status events.
    ///
    /// These events arrive as SSH user events rather than ordinary channel data.
    /// The handler records the execution status and defers completion until the
    /// channel closes so that trailing output is not lost.
    ///
    /// - Parameters:
    ///   - context: The current channel handler context.
    ///   - event: The inbound user event.
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is ChannelSuccessEvent:
            // Exec request was accepted by the server.
            execAcknowledged = true

        case is ChannelFailureEvent:
            // Exec request was rejected; close and fail.
            completePromises(exitStatus: nil, error: SSHClientError.commandExecFailed)
            context.close(promise: nil)

        case let exit as SSHChannelRequestEvent.ExitStatus:
            exitStatus = exit.exitStatus

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    /// Finalise the promises when the remote side closes the channel.
    ///
    /// Channel inactivity is the final signal that no more output can arrive, so
    /// the handler only resolves its promises at that point.
    ///
    /// - Parameter context: The current channel handler context.
    func channelInactive(context: ChannelHandlerContext) {
        completeIfPossible()
        context.fireChannelInactive()
    }

    /// Fail or complete any unresolved promises when the handler is removed.
    ///
    /// This defensive path prevents callers from waiting indefinitely if the
    /// pipeline removes the handler before normal channel shutdown finishes.
    ///
    /// - Parameter context: The current channel handler context.
    func handlerRemoved(context: ChannelHandlerContext) {
        // If we never completed, fail the promise to unblock waiters.
        if completePromise != nil {
            if let exitStatus {
                completePromises(exitStatus: exitStatus, error: nil)
            } else {
                completePromises(exitStatus: nil, error: SSHClientError.commandExecFailed)
            }
        }
    }

    /// Resolve the stored promises if an exit status is available.
    ///
    /// A missing exit status is treated as command-execution failure because the
    /// client cannot otherwise determine whether the remote request completed.
    private func completeIfPossible() {
        guard completePromise != nil else {
            return
        }

        guard let exitStatus else {
            completePromises(exitStatus: nil, error: SSHClientError.commandExecFailed)
            return
        }

        completePromises(exitStatus: exitStatus, error: nil)
    }

    /// Resolve all promises from the buffered state.
    ///
    /// Buffered output is always published together with either the final exit
    /// status or the terminal error so the caller can inspect partial output when
    /// an execution failure occurs.
    ///
    /// - Parameters:
    ///   - exitStatus: The exit status to publish.
    ///   - error: An error to use instead of a successful completion.
    private func completePromises(exitStatus: Int?, error: Error?) {
        if let promise = completePromise {
            completePromise = nil
            if let error = error {
                promise.fail(error)
            } else {
                promise.succeed(exitStatus ?? -1)
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

    /// Forward outbound writes unchanged.
    ///
    /// The handler does not transform outbound traffic. It remains in the
    /// pipeline only to observe inbound command-execution state.
    ///
    /// - Parameters:
    ///   - context: The current channel handler context.
    ///   - data: The outbound data.
    ///   - promise: The write completion promise.
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        // This handler does not write any data outbound by itself
        context.write(data, promise: promise)
    }
}
