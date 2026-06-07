//
//  SSHAgentSignature.swift
//
//  Copyright © 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 7/3/2026.
//
import Foundation
import NIOSSH

/// Helper for mapping SSH agent signatures to `NIOSSH` signatures.
///
/// The SSH agent protocol returns algorithm-labelled signature payloads in SSH
/// wire format. `SSHAgentSignature` centralises the logic that chooses signing
/// flags for outgoing requests and converts those wire-format replies into the
/// concrete `NIOSSHSignature` values expected by user-authentication code.
enum SSHAgentSignature {
    /// Determine the preferred agent signing flags for a public key.
    ///
    /// RSA keys can request stronger SHA-2 based signature algorithms when the
    /// package is built with the `RSA` trait. Other key types use the agent's
    /// default signing behaviour.
    static func preferredSigningFlags(for publicKey: NIOSSHPublicKey) -> SSHAgentSignFlags {
        let keyType = String(openSSHPublicKey: publicKey).split(separator: " ").first.map(String.init) ?? ""

        switch keyType {
        case "ssh-rsa":
            #if SSHCLIENT_RSA
            return .rsaSha2_512
            #else
            return []
            #endif
        default:
            return []
        }
    }

    /// Convert an SSH agent reply into a `NIOSSH` signature value.
    ///
    /// The conversion inspects the public-key algorithm first so it can validate
    /// the wire-format signature payload against the algorithms that are valid
    /// for that key. RSA signatures are only accepted when RSA support is enabled
    /// for the package build.
    ///
    /// - Parameters:
    ///   - signatureData: Raw signature payload returned by the SSH agent.
    ///   - publicKey: Public key used to validate the expected signature type.
    ///   - debug: Whether to emit diagnostic output during parsing.
    /// - Returns: A `NIOSSHSignature` matching the key type and reply payload.
    /// - Throws: `SSHAgentError` if the payload is malformed or incompatible.
    static func convertToNIOSSH(_ signatureData: Data, for publicKey: NIOSSHPublicKey, debug: Bool = false) throws -> NIOSSHSignature {
        let keyType = String(openSSHPublicKey: publicKey).split(separator: " ").first.map(String.init) ?? ""

        switch keyType {
        case "ssh-ed25519":
            let signature = try readSignature(from: signatureData, expectedTypes: ["ssh-ed25519"], debug: debug)
            guard signature.bytes.count == 64 else {
                throw SSHAgentError.signingFailed("Invalid Ed25519 signature length: \(signature.bytes.count)")
            }
            return .ed25519(signature: signature.bytes)
        case "ecdsa-sha2-nistp256":
            let signature = try readSignature(from: signatureData, expectedTypes: ["ecdsa-sha2-nistp256"], debug: debug)
            return try .ecdsaP256(signature: signature.bytes)
        case "ecdsa-sha2-nistp384":
            let signature = try readSignature(from: signatureData, expectedTypes: ["ecdsa-sha2-nistp384"], debug: debug)
            return try .ecdsaP384(signature: signature.bytes)
        case "ecdsa-sha2-nistp521":
            let signature = try readSignature(from: signatureData, expectedTypes: ["ecdsa-sha2-nistp521"], debug: debug)
            return try .ecdsaP521(signature: signature.bytes)
        case "ssh-rsa":
            #if SSHCLIENT_RSA
            let signature = try readSignature(
                from: signatureData,
                expectedTypes: ["rsa-sha2-256", "rsa-sha2-512"],
                debug: debug
            )

            switch signature.algorithm {
            case "rsa-sha2-256":
                return .rsaSHA256(signature: signature.bytes)
            case "rsa-sha2-512":
                return .rsaSHA512(signature: signature.bytes)
            default:
                throw SSHAgentError.signingFailed("Unsupported RSA signature algorithm: \(signature.algorithm)")
            }
            #else
            throw SSHAgentError.signingFailed("RSA support requires the RSA trait")
            #endif
        default:
            throw SSHAgentError.keyParsingFailed("Unsupported key type: \(keyType)")
        }
    }

    /// Read a wire-format agent signature and validate its algorithm label.
    ///
    /// SSH agent replies encode the signature algorithm and signature bytes as
    /// length-prefixed fields. This helper parses that structure once so callers
    /// can focus on key-specific conversion.
    ///
    /// - Parameters:
    ///   - signatureData: Raw signature payload from the SSH agent.
    ///   - expectedTypes: Set of acceptable algorithm names for the payload.
    ///   - debug: Whether to emit diagnostic output during parsing.
    /// - Returns: The parsed algorithm label and raw signature bytes.
    /// - Throws: `SSHAgentError` if the payload is truncated or uses an unexpected algorithm.
    private static func readSignature(
        from signatureData: Data,
        expectedTypes: Set<String>,
        debug: Bool
    ) throws -> (algorithm: String, bytes: Data) {
        var offset = 0

        func readUInt32() throws -> UInt32 {
            guard offset + 4 <= signatureData.count else {
                throw SSHAgentError.signingFailed("Invalid signature format: truncated length field")
            }

            let value = signatureData.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
                $0.loadUnaligned(as: UInt32.self).bigEndian
            }
            offset += 4
            return value
        }

        func readData(length: Int, label: String) throws -> Data {
            guard offset + length <= signatureData.count else {
                throw SSHAgentError.signingFailed("Invalid signature format: truncated \(label)")
            }

            let value = signatureData.subdata(in: offset..<(offset + length))
            offset += length
            return value
        }

        let algorithmLength = try readUInt32()
        let algorithmData = try readData(length: Int(algorithmLength), label: "algorithm")
        guard let algorithm = String(data: algorithmData, encoding: .utf8) else {
            throw SSHAgentError.signingFailed("Invalid signature format: algorithm is not UTF-8")
        }

        if debug {
            print("[SSHAgent] Signature algorithm: \(algorithm)")
        }

        guard expectedTypes.contains(algorithm) else {
            throw SSHAgentError.signingFailed(
                "Unexpected signature algorithm: \(algorithm), expected one of \(expectedTypes.sorted())"
            )
        }

        let signatureLength = try readUInt32()
        let signatureBytes = try readData(length: Int(signatureLength), label: "signature")

        if debug {
            print("[SSHAgent] Extracted signature: \(signatureBytes.count) bytes")
        }

        return (algorithm, signatureBytes)
    }
}
