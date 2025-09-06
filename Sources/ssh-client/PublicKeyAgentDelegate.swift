//
//  PublicKeyAgentDelegate.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Crypto
import Dispatch
import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOSSH

final class PublicKeyAgentDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let queue: DispatchQueue
    private let username: String?
    private let debug: Bool

    init(username: String?, password: String?, debug: Bool = false) {
        self.username = username
        self.queue = DispatchQueue(label: "io.swiftnio.ssh.PublicKeyAgentDelegate")
        self.debug = debug
        Task {
            await SSHAgent.shared.setDebug(debug)
        }
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        guard availableMethods.contains(.publicKey) else {
            fputs("[ssh-client] Public key authentication not supported\n", stderr)
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
            fputs("[ssh-client] No suitable public key found in ssh-agent\n", stderr)
            nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
            return
        }

        do {
            let agentBackedPrivateKey = try await agent.createNIOSSHPrivateKey(for: agentKey)
            let agentPublicKeyString = String(openSSHPublicKey: agentKey.publicKey)
            let keyType = agentPublicKeyString.split(separator: " ").first ?? "unknown"

            if debug {
                print("[ssh-client] Using SSH agent key: \(agentKey.comment)")
                print("[ssh-client] Key type: \(keyType)")
            }

            let offer = NIOSSHUserAuthenticationOffer(
                username: self.username ?? NSUserName(),
                serviceName: "ssh-connection",
                offer: .privateKey(.init(privateKey: agentBackedPrivateKey))
            )
            nextChallengePromise.succeed(offer)
        } catch {
            fputs("[ssh-client] Error creating agent-backed private key: \(error)\n", stderr)
            nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
        }
    }
}

