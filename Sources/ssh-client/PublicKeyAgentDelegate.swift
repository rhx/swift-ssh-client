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

        if debug {
            print("[debug] SSH Agent Integration Status - Implementation Complete:")
            print("[debug] - Found agent key: \(agentKey.comment)")
            let keyType = String(openSSHPublicKey: agentKey.publicKey).split(separator: " ").first ?? "unknown"
            print("[debug] - Key type: \(keyType)")
            print("[debug] - Agent public key: \(String(openSSHPublicKey: agentKey.publicKey))")
            print("[debug] - NIOSSH API Analysis: Signing interface not extensible")
            print("[debug] - Architectural Plan: Created in SSHAgent.md")
            print("[debug] - Current Status: SSH agent authentication requires NIOSSH modifications")
        }

        // SSH AGENT INTEGRATION - Using NIOSSH Fork with Signing Delegate Support:
        //
        // The NIOSSH fork has been updated with:
        // 1. NIOSSHSigningDelegate protocol - Public signing delegation interface
        // 2. UserAuthSignablePayload - Made public for signing delegates
        // 3. NIOSSHSignature - Added public constructors for signing delegates
        // 4. NIOSSHPrivateKey - Added signingDelegate backing key case
        //
        // This enables proper SSH agent integration with minimal NIOSSH changes.

        do {
            // Create SSH agent signing delegate
            let signingDelegate = SSHAgentSigningDelegate(
                agentKey: agentKey,
                agent: agent,
                debug: debug
            )

            if debug {
                print("[debug] Created SSH agent signing delegate")
            }

            // Create NIOSSH private key with signing delegate
            let agentBackedPrivateKey = NIOSSHPrivateKey(
                signingDelegate: signingDelegate,
                publicKey: agentKey.publicKey
            )

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
            fputs("[ssh-client] Error creating SSH agent signing delegate: \(error)\n", stderr)
            if debug {
                print("[debug] SSH agent signing delegate creation failed: \(String(describing: error))")
            }
            nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
        }
    }
}

