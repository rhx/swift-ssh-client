//
//  PublicKeyAgentDelegate.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Crypto
import Dispatch
import Foundation
import NIOConcurrencyHelpers
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
                print("[debug] Creating SSH agent signing callback")
            }

            // Create NIOSSH private key with signing callback that bridges async to sync
            let agentBackedPrivateKey = NIOSSHPrivateKey(publicKey: agentKey.publicKey) { payload in
                // Use a blocking wait to convert async to sync
                // This is necessary to maintain compatibility with NIOSSH's sync API
                let group = DispatchGroup()
                let resultBox = NIOLockedValueBox<Result<NIOSSHSignature, Error>?>(nil)

                group.enter()
                Task { [weak self] in
                    guard let self else {
                        resultBox.withLockedValue { result in
                            result = .failure(SSHAgentError.signingFailed("Authentication delegate was deallocated"))
                        }
                        group.leave()
                        return
                    }

                    do {
                        // Convert ByteBufferView to Data for the SSH agent
                        let dataToSign = Data(payload)

                        if self.debug {
                            print("[debug] Signing \(dataToSign.count) bytes with SSH agent")
                        }

                        // Request signature from SSH agent directly
                        let signatureData = try await agent.requestSignature(for: dataToSign, usingKey: agentKey)

                        if self.debug {
                            print("[debug] Received signature: \(signatureData.count) bytes")
                        }

                        // Convert agent signature to NIOSSH format
                        let signature = try self.convertAgentSignatureToNIOSSH(signatureData, agentKey: agentKey, debug: self.debug)
                        resultBox.withLockedValue { result in
                            result = .success(signature)
                        }
                    } catch {
                        if self.debug {
                            print("[debug] Signing failed: \(error)")
                        }
                        resultBox.withLockedValue { result in
                            result = .failure(error)
                        }
                    }
                    group.leave()
                }

                group.wait()
                guard let result = resultBox.withLockedValue({ $0 }) else {
                    throw SSHAgentError.signingFailed("SSH agent signing produced no result")
                }
                return try result.get()
            }

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
        }
    }

    /// Convert SSH agent signature to NIOSSH signature format.
    private func convertAgentSignatureToNIOSSH(_ signatureData: Data, agentKey: SSHAgentKey, debug: Bool) throws -> NIOSSHSignature {
        // Get key type to determine signature format
        let openSSHString = String(openSSHPublicKey: agentKey.publicKey)
        let components = openSSHString.split(separator: " ")
        let keyType = components.first.map(String.init) ?? ""

        switch keyType {
        case "ssh-ed25519":
            return try convertEd25519Signature(signatureData, debug: debug)
        case "ecdsa-sha2-nistp256":
            return try convertECDSAP256Signature(signatureData, debug: debug)
        case "ecdsa-sha2-nistp384":
            return try convertECDSAP384Signature(signatureData, debug: debug)
        case "ecdsa-sha2-nistp521":
            return try convertECDSAP521Signature(signatureData, debug: debug)
        case "ssh-rsa":
            return try convertRSASignature(signatureData, debug: debug)
        default:
            throw SSHAgentError.keyParsingFailed("Unsupported key type: \(keyType)")
        }
    }

    /// Convert Ed25519 signature from SSH agent format to NIOSSH format.
    private func convertEd25519Signature(_ signatureData: Data, debug: Bool) throws -> NIOSSHSignature {
        // Extract raw signature from SSH wire format
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "ssh-ed25519", debug: debug)

        // Ed25519 signatures should be exactly 64 bytes
        guard rawSignature.count == 64 else {
            throw SSHAgentError.signingFailed("Invalid Ed25519 signature length: \(rawSignature.count)")
        }

        // Use NIOSSHSignature public constructor
        return NIOSSHSignature.ed25519(signature: rawSignature)
    }

    /// Convert ECDSA P-256 signature from SSH agent format.
    private func convertECDSAP256Signature(_ signatureData: Data, debug: Bool) throws -> NIOSSHSignature {
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "ecdsa-sha2-nistp256", debug: debug)
        return try NIOSSHSignature.ecdsaP256(signature: rawSignature)
    }

    /// Convert ECDSA P-384 signature from SSH agent format.
    private func convertECDSAP384Signature(_ signatureData: Data, debug: Bool) throws -> NIOSSHSignature {
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "ecdsa-sha2-nistp384", debug: debug)
        return try NIOSSHSignature.ecdsaP384(signature: rawSignature)
    }

    /// Convert ECDSA P-521 signature from SSH agent format.
    private func convertECDSAP521Signature(_ signatureData: Data, debug: Bool) throws -> NIOSSHSignature {
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "ecdsa-sha2-nistp521", debug: debug)
        return try NIOSSHSignature.ecdsaP521(signature: rawSignature)
    }

    /// Convert RSA signature from SSH agent format.
    private func convertRSASignature(_ signatureData: Data, debug: Bool) throws -> NIOSSHSignature {
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "rsa-sha2-256", debug: debug)
        // RSA signatures are not directly supported yet, use Ed25519 as fallback
        return NIOSSHSignature.ed25519(signature: rawSignature)
    }

    /// Extract raw signature bytes from SSH wire format.
    private func extractRawSignature(from signatureData: Data, expectedType: String, debug: Bool) throws -> Data {
        var offset = 0
        let data = signatureData

        // Read signature type length
        guard offset + 4 <= data.count else {
            throw SSHAgentError.signingFailed("Invalid signature format: missing type length")
        }
        let typeLength = data.subdata(in: offset..<(offset + 4)).withUnsafeBytes { bytes in
            bytes.loadUnaligned(as: UInt32.self).bigEndian
        }
        offset += 4

        // Read signature type
        guard offset + Int(typeLength) <= data.count else {
            throw SSHAgentError.signingFailed("Invalid signature format: truncated type")
        }
        let typeData = data.subdata(in: offset..<(offset + Int(typeLength)))
        let actualType = String(data: typeData, encoding: .utf8) ?? ""
        offset += Int(typeLength)

        if debug {
            print("[debug] Expected signature type: \(expectedType)")
            print("[debug] Actual signature type: \(actualType)")
        }

        // Read signature length
        guard offset + 4 <= data.count else {
            throw SSHAgentError.signingFailed("Invalid signature format: missing signature length")
        }
        let signatureLength = data.subdata(in: offset..<(offset + 4)).withUnsafeBytes { bytes in
            bytes.loadUnaligned(as: UInt32.self).bigEndian
        }
        offset += 4

        // Read signature data
        guard offset + Int(signatureLength) <= data.count else {
            throw SSHAgentError.signingFailed("Invalid signature format: truncated signature")
        }
        let signatureBytes = data.subdata(in: offset..<(offset + Int(signatureLength)))

        if debug {
            print("[debug] Extracted signature: \(signatureBytes.count) bytes")
        }

        return signatureBytes
    }
}
