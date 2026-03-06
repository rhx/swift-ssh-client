//
//  InteractiveShellHandler.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 8/3/2026.
//
import Dispatch
import NIOCore
import NIOPosix
import NIOSSH

final class InteractiveShellHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    private enum RequestState {
        case waitingForPseudoTerminal
        case waitingForShell
        case running
    }

    private var completePromise: EventLoopPromise<Int>?
    private let pseudoTerminalRequest: SSHChannelRequestEvent.PseudoTerminalRequest
    private var requestState: RequestState = .waitingForPseudoTerminal
    private var exitStatus: Int?

    init(
        pseudoTerminalRequest: SSHChannelRequestEvent.PseudoTerminalRequest,
        completePromise: EventLoopPromise<Int>
    ) {
        self.pseudoTerminalRequest = pseudoTerminalRequest
        self.completePromise = completePromise
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let setOption = context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
        setOption.assumeIsolated().whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        let (ours, theirs) = GlueHandler.matchedPair()
        let loopBoundGlueHandler = NIOLoopBound(theirs, eventLoop: context.eventLoop)
        let loopBoundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let pseudoTerminalRequest = self.pseudoTerminalRequest

        do {
            try context.channel.pipeline.syncOperations.addHandler(ours, position: .last)

            DispatchQueue(label: "interactive shell bootstrap").async { [eventLoop = context.eventLoop] in
                let bootstrap = NIOPipeBootstrap(group: eventLoop)
                bootstrap.channelOption(.allowRemoteHalfClosure, value: true).channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandlers(loopBoundGlueHandler.value)
                    }
                }.takingOwnershipOfDescriptors(input: 0, output: 1).whenComplete { result in
                    let context = loopBoundContext.value
                    switch result {
                    case .success:
                        context.triggerUserOutboundEvent(pseudoTerminalRequest).assumeIsolated().whenFailure { error in
                            context.fireErrorCaught(error)
                            context.close(promise: nil)
                        }
                    case .failure(let error):
                        context.fireErrorCaught(error)
                    }
                }
            }
        } catch {
            context.fireErrorCaught(error)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is ChannelSuccessEvent:
            switch self.requestState {
            case .waitingForPseudoTerminal:
                self.requestState = .waitingForShell
                let shellRequest = SSHChannelRequestEvent.ShellRequest(wantReply: true)
                context.triggerUserOutboundEvent(shellRequest, promise: nil)
            case .waitingForShell:
                self.requestState = .running
            case .running:
                break
            }

        case is ChannelFailureEvent:
            self.failIfNeeded(SSHClientError.commandExecFailed)
            context.close(promise: nil)

        case let exit as SSHChannelRequestEvent.ExitStatus:
            self.exitStatus = exit.exitStatus

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(let bytes) = data.data else {
            return
        }

        switch data.type {
        case .channel:
            context.fireChannelRead(self.wrapInboundOut(bytes))
        case .stdErr:
            bytes.withUnsafeReadableBytes { str in
                let rc = writeToFD(STDERR_FILENO, str.baseAddress!, str.count)
                precondition(rc == str.count)
            }
        default:
            break
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if let exitStatus {
            self.succeedIfNeeded(exitStatus)
        } else {
            self.failIfNeeded(SSHClientError.commandExecFailed)
        }
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        if let exitStatus {
            self.succeedIfNeeded(exitStatus)
        } else {
            self.failIfNeeded(SSHClientError.commandExecFailed)
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(data))), promise: promise)
    }

    private func succeedIfNeeded(_ exitStatus: Int) {
        if let promise = self.completePromise {
            self.completePromise = nil
            promise.succeed(exitStatus)
        }
    }

    private func failIfNeeded(_ error: Error) {
        if let promise = self.completePromise {
            self.completePromise = nil
            promise.fail(error)
        }
    }
}

@inlinable
func writeToFD(_ fd: Int32, _ buf: UnsafeRawPointer!, _ nbyte: Int) -> Int {
    write(fd, buf, nbyte)
}
