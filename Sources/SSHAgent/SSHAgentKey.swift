//
//  SSHAgentKey.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore
import NIOSSH

/// A representation of an SSH key from the agent.
///
/// This structure encapsulates the key data and metadata returned by an SSH agent,
/// providing access to both the raw key blob and the public key representation
/// needed for SSH authentication operations.
///
/// The key maintains the original binary representation as received from the agent
/// whilst also providing convenient access to the parsed public key for use with
/// the NIOSSH framework. Comments associated with keys in the agent are preserved
/// to assist with key identification and debugging.
public struct SSHAgentKey {
    /// The raw key blob as returned by the SSH agent
    public let keyBlob: Data
    /// The parsed public key for use with NIOSSH
    public let publicKey: NIOSSHPublicKey
    /// The key comment/description from the agent
    public let comment: String

    /// Creates a new SSH agent key representation.
    ///
    /// This initialiser processes the raw key data from an SSH agent response,
    /// parsing the binary key blob into a public key structure suitable for
    /// use with SSH authentication protocols.
    ///
    /// - Parameter keyBlob: The raw binary key data from the agent
    /// - Parameter comment: The descriptive comment associated with the key
    /// - Parameter debug: Whether to print debug information during key parsing
    /// - Throws: `NIOSSHError` if the key cannot be parsed or is of an unsupported type
    public init(keyBlob: Data, comment: String, debug: Bool = false) throws {
        self.keyBlob = keyBlob
        self.comment = comment

        // Convert the binary key blob to OpenSSH public key format
        let openSSHString = try Self.convertKeyBlobToOpenSSHFormat(keyBlob, debug: debug)
        self.publicKey = try NIOSSHPublicKey(openSSHPublicKey: openSSHString)
    }

    /// Converts a binary key blob to OpenSSH public key string format.
    ///
    /// This method parses the SSH wire format key blob and converts it to the
    /// standard OpenSSH public key string format that can be parsed by NIOSSH.
    ///
    /// - Parameter keyBlob: The binary key data from the SSH agent
    /// - Parameter debug: Whether to print debug information during conversion
    /// - Returns: An OpenSSH format public key string
    /// - Throws: `SSHAgentError` if the key format is not recognised or supported
    static func convertKeyBlobToOpenSSHFormat(_ keyBlob: Data, debug: Bool = false) throws -> String {
        var offset = 0

        func readUInt32() throws -> UInt32 {
            guard offset + 4 <= keyBlob.count else {
                throw SSHAgentError.invalidKeyData("Key blob too short for UInt32 at offset \(offset)")
            }
            let val = keyBlob.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
                $0.load(as: UInt32.self).bigEndian
            }
            offset += 4
            return val
        }
        func readData(_ length: Int) throws -> Data {
            guard offset + length <= keyBlob.count else {
                throw SSHAgentError.invalidKeyData("Key blob too short for data of length \(length) at offset \(offset)")
            }
            let d = keyBlob.subdata(in: offset..<(offset + length))
            offset += length
            return d
        }
        func readString() throws -> Data {
            let len = try readUInt32()
            return try readData(Int(len))
        }
        // Read algorithm name
        let algorithmNameData = try readString()
        guard let algorithmName = String(data: algorithmNameData, encoding: .utf8) else {
            throw SSHAgentError.invalidKeyData("Invalid algorithm name encoding")
        }
        if debug { print("[SSHAgent] Parsing key type: \(algorithmName)") }
        switch algorithmName {
        case "ssh-ed25519":
            // [string "ssh-ed25519"][string pubkey]
            let pubkey = try readString()
            if debug { print("[SSHAgent] Parsed ed25519 pubkey (len: \(pubkey.count))") }
            var blob = Data()
            var nameLen = UInt32(algorithmNameData.count).bigEndian
            blob.append(Data(bytes: &nameLen, count: 4))
            blob.append(algorithmNameData)
            var pubkeyLen = UInt32(pubkey.count).bigEndian
            blob.append(Data(bytes: &pubkeyLen, count: 4))
            blob.append(pubkey)
            let base64KeyData = blob.base64EncodedString()
            if debug { print("[SSHAgent] ed25519 OpenSSH string: ssh-ed25519 \(base64KeyData.prefix(16))...") }
            return "ssh-ed25519 \(base64KeyData)"
        case "ssh-rsa":
            // [string "ssh-rsa"][mpint e][mpint n]
            let e = try readString()
            let n = try readString()
            func printMpint(_ label: String, _ data: Data) {
                if debug {
                    print("[SSHAgent] RSA \(label) (len: \(data.count)): 0x" + data.map { String(format: "%02x", $0) }.joined())
                    print("[SSHAgent] RSA \(label) (base64): \(data.base64EncodedString())")
                }
            }
            if debug { print("[SSHAgent] Parsed rsa exponent (e, len: \(e.count)), modulus (n, len: \(n.count))") }
            printMpint("exponent", e)
            printMpint("modulus", n)
            // Check for mpint encoding issues (should be minimal, no unnecessary leading zero unless high bit set)
            func minimalMpint(_ data: Data) -> Data {
                if data.count > 1 && data.first == 0x00 && (data[1] & 0x80) == 0 {
                    // Unnecessary leading zero, strip it
                    return data.dropFirst()
                }
                return data
            }
            let eFixed = minimalMpint(e)
            let nFixed = minimalMpint(n)
            if eFixed.count != e.count || nFixed.count != n.count {
                if debug { print("[SSHAgent] Fixed mpint encoding: exponent len \(eFixed.count), modulus len \(nFixed.count)") }
            }
            var blob = Data()
            var nameLen = UInt32(algorithmNameData.count).bigEndian
            blob.append(Data(bytes: &nameLen, count: 4))
            blob.append(algorithmNameData)
            var eLen = UInt32(eFixed.count).bigEndian
            blob.append(Data(bytes: &eLen, count: 4))
            blob.append(eFixed)
            var nLen = UInt32(nFixed.count).bigEndian
            blob.append(Data(bytes: &nLen, count: 4))
            blob.append(nFixed)
            let base64KeyData = blob.base64EncodedString()
            if debug { print("[SSHAgent] rsa OpenSSH string: ssh-rsa \(base64KeyData.prefix(16))...") }
            return "ssh-rsa \(base64KeyData)"
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            // [string type][string curve][string Q]
            let curve = try readString()
            let Q = try readString()
            guard let curveName = String(data: curve, encoding: .utf8) else {
                throw SSHAgentError.invalidKeyData("Invalid ECDSA curve name")
            }
            if debug { print("[SSHAgent] Parsed ECDSA curve: \(curveName), Q len: \(Q.count)") }
            var blob = Data()
            var nameLen = UInt32(algorithmNameData.count).bigEndian
            blob.append(Data(bytes: &nameLen, count: 4))
            blob.append(algorithmNameData)
            var curveLen = UInt32(curve.count).bigEndian
            blob.append(Data(bytes: &curveLen, count: 4))
            blob.append(curve)
            var QLen = UInt32(Q.count).bigEndian
            blob.append(Data(bytes: &QLen, count: 4))
            blob.append(Q)
            let base64KeyData = blob.base64EncodedString()
            if debug { print("[SSHAgent] ECDSA OpenSSH string: \(algorithmName) \(base64KeyData.prefix(16))...") }
            return "\(algorithmName) \(base64KeyData)"
        default:
            if debug { print("[SSHAgent] Unsupported or unknown key type: \(algorithmName). Skipping.") }
            throw SSHAgentError.keyParsingFailed("Unsupported or unknown key type: \(algorithmName)")
        }
    }
}
