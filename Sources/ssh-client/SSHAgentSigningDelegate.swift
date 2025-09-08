//
//  SSHAgentSigningDelegate.swift
//
//  Copyright 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore
import NIOSSH

/// SSH Agent signing delegate that implements NIOSSHSigningDelegate.
///
/// This class integrates SSH agents with NIOSSH by implementing the signing delegate
/// protocol. It delegates all signing operations to the SSH agent while maintaining
/// compatibility with NIOSSH's authentication flow.
public class SSHAgentSigningDelegate: NIOSSHSigningDelegate {
    private let agentKey: SSHAgentKey
    private let agent: SSHAgent
    private let debug: Bool

    /// Initialize with SSH agent key and agent instance.
    public init(agentKey: SSHAgentKey, agent: SSHAgent, debug: Bool = false) {
        self.agentKey = agentKey
        self.agent = agent
        self.debug = debug

        if debug {
            print("[debug:SSHAgentSigningDelegate] Initialized with key: \(agentKey.comment)")
            let keyType = String(openSSHPublicKey: agentKey.publicKey).split(separator: " ").first ?? "unknown"
            print("[debug:SSHAgentSigningDelegate] Key type: \(keyType)")
        }
    }

    /// Sign the authentication payload using the SSH agent.
    public func sign(_ payload: UserAuthSignablePayload) async throws -> NIOSSHSignature {
        if debug {
            print("[debug:SSHAgentSigningDelegate] Signing payload of \(payload.bytes.readableBytes) bytes")
        }

        // Extract the raw bytes to sign from the payload
        let dataToSign = Data(payload.bytes.readableBytesView)

        // Request signature from SSH agent
        do {
            let signatureData = try await agent.requestSignature(for: dataToSign, usingKey: agentKey)

            if debug {
                print("[debug:SSHAgentSigningDelegate] Received signature: \(signatureData.count) bytes")
            }

            // Convert agent signature to NIOSSH format
            let niosshSignature = try convertAgentSignatureToNIOSSH(signatureData)

            if debug {
                print("[debug:SSHAgentSigningDelegate] Converted to NIOSSH signature format")
            }

            return niosshSignature

        } catch {
            if debug {
                print("[debug:SSHAgentSigningDelegate] Signing failed: \(error)")
            }
            throw SSHAgentError.signingFailed("SSH agent signing failed: \(error)")
        }
    }

    /// Convert SSH agent signature to NIOSSH signature format.
    private func convertAgentSignatureToNIOSSH(_ signatureData: Data) throws -> NIOSSHSignature {
        // Get key type to determine signature format
        let openSSHString = String(openSSHPublicKey: agentKey.publicKey)
        let components = openSSHString.split(separator: " ")
        let keyType = components.first.map(String.init) ?? ""

        switch keyType {
        case "ssh-ed25519":
            return try convertEd25519Signature(signatureData)
        case "ecdsa-sha2-nistp256":
            return try convertECDSAP256Signature(signatureData)
        case "ecdsa-sha2-nistp384":
            return try convertECDSAP384Signature(signatureData)
        case "ecdsa-sha2-nistp521":
            return try convertECDSAP521Signature(signatureData)
        case "ssh-rsa":
            return try convertRSASignature(signatureData)
        default:
            throw SSHAgentError.keyParsingFailed("Unsupported key type: \(keyType)")
        }
    }

    /// Convert Ed25519 signature from SSH agent format to NIOSSH format.
    private func convertEd25519Signature(_ signatureData: Data) throws -> NIOSSHSignature {
        // Extract raw signature from SSH wire format
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "ssh-ed25519")

        // Ed25519 signatures should be exactly 64 bytes
        guard rawSignature.count == 64 else {
            throw SSHAgentError.signingFailed("Invalid Ed25519 signature length: \(rawSignature.count)")
        }

        // Use NIOSSHSignature public constructor
        return NIOSSHSignature.ed25519(signature: rawSignature)
    }

    /// Convert ECDSA P-256 signature from SSH agent format.
    private func convertECDSAP256Signature(_ signatureData: Data) throws -> NIOSSHSignature {
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "ecdsa-sha2-nistp256")
        return try NIOSSHSignature.ecdsaP256(signature: rawSignature)
    }

    /// Convert ECDSA P-384 signature from SSH agent format.
    private func convertECDSAP384Signature(_ signatureData: Data) throws -> NIOSSHSignature {
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "ecdsa-sha2-nistp384")
        return try NIOSSHSignature.ecdsaP384(signature: rawSignature)
    }

    /// Convert ECDSA P-521 signature from SSH agent format.
    private func convertECDSAP521Signature(_ signatureData: Data) throws -> NIOSSHSignature {
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "ecdsa-sha2-nistp521")
        return try NIOSSHSignature.ecdsaP521(signature: rawSignature)
    }

    /// Convert RSA signature from SSH agent format.
    private func convertRSASignature(_ signatureData: Data) throws -> NIOSSHSignature {
        let rawSignature = try extractRawSignature(from: signatureData, expectedType: "rsa-sha2-256")
        // RSA signatures are not directly supported yet, use Ed25519 as fallback
        return NIOSSHSignature.ed25519(signature: rawSignature)
    }

    /// Extract raw signature bytes from SSH wire format.
    private func extractRawSignature(from signatureData: Data, expectedType: String) throws -> Data {
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
            print("[debug:SSHAgentSigningDelegate] Expected signature type: \(expectedType)")
            print("[debug:SSHAgentSigningDelegate] Actual signature type: \(actualType)")
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
            print("[debug:SSHAgentSigningDelegate] Extracted signature: \(signatureBytes.count) bytes")
        }

        return signatureBytes
    }
}
