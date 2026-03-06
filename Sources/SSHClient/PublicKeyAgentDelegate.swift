//
//  PublicKeyAgentDelegate.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Crypto
import Dispatch
import Foundation
import NIOCore
import NIOSSH
import SSHAgent

final class PublicKeyAgentDelegate: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    private let queue: DispatchQueue
    private let username: String?
    private let debug: Bool

    init(username: String?, password: String? = nil, debug: Bool = false) {
        self.username = username
        self.queue = DispatchQueue(label: "io.swiftnio.ssh.PublicKeyAgentDelegate")
        self.debug = debug
        Task {
            await SSHAgent.shared.setDebug(debug)
        }
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        guard availableMethods.contains(.publicKey) else {
            if debug { print("[ssh-client] Public key authentication not supported") }
            nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
            return
        }

        queue.async {
            Task {
                await self.attemptAgentAuthentication(nextChallengePromise: nextChallengePromise)
            }
        }
    }

    private func attemptAgentAuthentication(nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) async {
        let agent = SSHAgent.shared
        let preferredKeyTypes = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"]

        guard let agentKey = await agent.findKey(for: preferredKeyTypes) else {
            if debug { print("[ssh-client] No suitable public key found in ssh-agent") }
            nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
            return
        }

        if debug {
            print("[debug] SSH agent integration active")
            print("[debug] - Found agent key: \(agentKey.comment)")
            let keyType = String(openSSHPublicKey: agentKey.publicKey).split(separator: " ").first ?? "unknown"
            print("[debug] - Key type: \(keyType)")
            print("[debug] - Agent public key: \(String(openSSHPublicKey: agentKey.publicKey))")
            print("[debug] - Signing delegate: enabled via swift-nio-ssh ssh-agent branch")
            print("[debug] - Current status: user-authentication signatures are delegated to ssh-agent")
        }

        do {
            if debug {
                print("[debug] Creating SSH agent-backed private key")
            }

            let agentBackedPrivateKey = try await agent.createNIOSSHPrivateKey(for: agentKey)

            if debug {
                print("[debug] Created agent-backed private key")
                print("[debug] Agent public key: \(String(openSSHPublicKey: agentKey.publicKey))")
            }

            // Create authentication offer
            let offer = NIOSSHUserAuthenticationOffer(
                username: self.username ?? NSUserName(),
                serviceName: "ssh-connection",
                offer: .privateKey(.init(privateKey: agentBackedPrivateKey))
            )

            if debug {
                print("[debug] Created authentication offer with SSH agent signing delegate")
            }

            nextChallengePromise.succeed(offer)
        } catch {
            if debug {
                print("[debug] Failed to create agent-backed private key: \(error)")
            }
            nextChallengePromise.fail(error)
        }
    }
}
