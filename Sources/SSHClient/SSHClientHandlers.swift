//
//  SSHClientHandlers.swift
//
//  Copyright 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Supporting handlers for SSH client functionality
//
import Foundation
import NIOCore
import NIOPosix
import NIOSSH
import SSHAgent

// MARK: - Error Handler

final class ErrorHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Do not print here; the client will handle errors appropriately
        context.close(promise: nil)
    }
}

// MARK: - Host Key Delegate

final class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        validationCompletePromise.succeed(())
    }
}

// MARK: - Debug Handler

final class SSHChildDebugHandler: ChannelDuplexHandler, @unchecked Sendable {
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

// MARK: - Authentication Delegates

/// A composite authentication delegate that tries multiple authentication methods in sequence.
final class CompositeAuthDelegate: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    private let username: String?
    private let password: String?
    private let debug: Bool
    private var attemptedMethods: Set<String> = []

    init(username: String? = nil, password: String? = nil, debug: Bool = false) {
        self.username = username
        self.password = password
        self.debug = debug
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        // Try SSH agent authentication first if available and not yet attempted
        if availableMethods.contains(.publicKey) && !attemptedMethods.contains("publickey") {
            attemptedMethods.insert("publickey")
            if debug { print("[debug] Attempting SSH agent public key authentication...") }

            let agentDelegate = PublicKeyAgentDelegate(username: username, password: password, debug: debug)
            agentDelegate.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
            return
        }

        // Fall back to password authentication if available and not yet attempted
        if availableMethods.contains(.password) && !attemptedMethods.contains("password") {
            attemptedMethods.insert("password")
            if debug { print("[debug] Falling back to password authentication...") }

            let passwordDelegate = InteractivePasswordPromptDelegate(username: username, password: password, debug: debug)
            passwordDelegate.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
            return
        }

        // No more authentication methods to try
        if debug { print("[debug] No more authentication methods available") }
        nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
    }
}

/// Interactive password authentication delegate.
final class InteractivePasswordPromptDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let username: String?
    private let password: String?
    private let debug: Bool

    init(username: String?, password: String?, debug: Bool = false) {
        self.username = username
        self.password = password
        self.debug = debug
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.password) else {
            if debug { print("[debug] Password authentication not supported") }
            nextChallengePromise.fail(SSHClientError.passwordAuthenticationNotSupported)
            return
        }

        guard let password = password else {
            if debug { print("[debug] No password provided") }
            nextChallengePromise.fail(SSHClientError.passwordAuthenticationNotSupported)
            return
        }

        if debug { print("[debug] Using provided password for authentication") }

        let offer = NIOSSHUserAuthenticationOffer(
            username: username ?? NSUserName(),
            serviceName: "ssh-connection",
            offer: .password(.init(password: password))
        )
        nextChallengePromise.succeed(offer)
    }
}
