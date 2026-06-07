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

/// Authentication delegate that sources public-key credentials from `ssh-agent`.
///
/// The executable uses this delegate to turn local agent keys into `NIOSSH`
/// public-key authentication offers. It mirrors the library behaviour whilst
/// routing user-visible diagnostics through the command-line stderr helpers.
final class PublicKeyAgentDelegate: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    private let queue: DispatchQueue
    private let username: String?
    private let debug: Bool

    /// Create a public-key delegate backed by the local SSH agent.
    ///
    /// The delegate stores the preferred user name for authentication and
    /// optionally enables diagnostic output for agent discovery and key selection.
    ///
    /// - Parameters:
    ///   - username: Preferred SSH user name, or `nil` to use the local account name.
    ///   - password: Unused compatibility parameter retained by the CLI wiring.
    ///   - debug: Whether to emit diagnostic output.
    init(username: String?, password: String? = nil, debug: Bool = false) {
        self.username = username
        self.queue = DispatchQueue(label: "io.swiftnio.ssh.PublicKeyAgentDelegate")
        self.debug = debug
        Task {
            await SSHAgent.shared.setDebug(debug)
        }
    }

    /// Request the next public-key authentication offer from the SSH agent.
    ///
    /// `NIOSSH` calls this method when the server advertises supported user-auth
    /// methods. The delegate only proceeds when public-key authentication is
    /// available, then schedules the agent lookup on its private queue.
    ///
    /// - Parameters:
    ///   - availableMethods: Authentication methods accepted by the server.
    ///   - nextChallengePromise: Promise to complete with the next authentication offer.
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        guard availableMethods.contains(.publicKey) else {
            writeStandardErrorLine("[ssh-client] Public key authentication not supported")
            nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
            return
        }

        queue.async {
            Task {
                await self.attemptAgentAuthentication(nextChallengePromise: nextChallengePromise)
            }
        }
    }

    /// Look up a suitable agent key and build a public-key authentication offer.
    ///
    /// The method prefers modern key types first and falls back to RSA when RSA
    /// support is available in the build. When a key is found, the delegate wraps
    /// it in an agent-backed private key so signature requests continue to flow
    /// back through the agent.
    ///
    /// - Parameter nextChallengePromise: Promise to complete with the authentication offer.
    private func attemptAgentAuthentication(nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) async {
        let agent = SSHAgent.shared
        let preferredKeyTypes = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"]

        guard let agentKey = await agent.findKey(for: preferredKeyTypes) else {
            writeStandardErrorLine("[ssh-client] No suitable public key found in ssh-agent")
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

        // The ssh-agent branch of swift-nio-ssh exposes a signing callback API that
        // lets the client delegate user-authentication signatures to ssh-agent.

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
