//
//  SSHAgentPrivateKey.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore
import NIOSSH

/// A private key implementation that delegates signing operations to the SSH agent.
///
/// This class provides a private key interface that delegates all cryptographic
/// operations to the SSH agent, ensuring that private key material never leaves
/// the agent's security boundary. It maintains a reference to the agent key and
/// communicates with the agent for signature generation operations.
///
/// The implementation provides a compatible interface with NIOSSH authentication
/// mechanisms whilst leveraging the SSH agent for all private key operations.
/// This approach maintains the security benefits of agent-based authentication
/// where sensitive cryptographic material remains protected within the agent.
///
/// ## Security Benefits
///
/// By delegating to the SSH agent, this implementation ensures:
/// - Private keys never leave the agent's security boundary
/// - Agent-specific policies and constraints are respected
/// - Hardware security modules can be used if supported by the agent
/// - Key usage can be audited and controlled by the agent
///
/// ## Agent Integration
///
/// The class communicates with the SSH agent using the standard SSH agent protocol,
/// sending signing requests and receiving signatures. All protocol details are
/// handled transparently, providing a simple interface for authentication use.
public class SSHAgentPrivateKey {
    private let agentKey: SSHAgentKey
    private let agent: SSHAgent

    /// The public key corresponding to this private key.
    ///
    /// This property provides access to the public key component extracted from
    /// the SSH agent key data. The public key can be safely shared for authentication
    /// purposes and contains all necessary information for key verification operations.
    public var publicKey: NIOSSHPublicKey {
        return agentKey.publicKey
    }

    /// Creates a new SSH agent-backed private key.
    ///
    /// This initialiser creates a private key interface that delegates signing
    /// operations to the specified SSH agent. The agent key contains the metadata
    /// and public key information needed for authentication, whilst the actual
    /// private key material remains securely stored within the agent.
    ///
    /// - Parameter agentKey: The SSH agent key to use for signing operations
    /// - Parameter agent: The SSH agent instance for communication
    public init(agentKey: SSHAgentKey, agent: SSHAgent) {
        self.agentKey = agentKey
        self.agent = agent
    }

    /// Signs data using the SSH agent.
    ///
    /// This method delegates the signing operation to the SSH agent, ensuring that
    /// private key material never needs to be exposed to the client application.
    /// The agent performs the cryptographic operation within its secure environment
    /// and returns the resulting signature.
    ///
    /// The signing process respects any key constraints or policies configured
    /// within the SSH agent, including usage limitations, time restrictions, and
    /// destination constraints. The agent determines the appropriate signing
    /// algorithm based on the key type and any provided preferences.
    ///
    /// ## Protocol Handling
    ///
    /// The method handles the SSH agent protocol details transparently:
    /// - Constructs properly formatted signing requests
    /// - Manages communication with the agent
    /// - Processes signature responses and error conditions
    /// - Converts agent signatures to NIOSSH-compatible format
    ///
    /// Different key types (RSA, Ed25519, ECDSA) are handled appropriately,
    /// with the agent determining the specific cryptographic operations needed.
    ///
    /// - Parameter data: The data to be signed
    /// - Returns: A signature compatible with NIOSSH authentication
    /// - Throws: Various errors if signing fails or agent communication fails
    public func sign<DataBytes: SendableData>(_ data: DataBytes) async throws -> Data {
        // Get the key type to determine the correct signature format
        let openSSHString = String(openSSHPublicKey: agentKey.publicKey)
        let components = openSSHString.split(separator: " ", maxSplits: 1)
        let keyType = components.first.map(String.init) ?? ""

        // Determine signing flags based on key type for optimal compatibility
        let flags = determineSigningFlags(for: agentKey.publicKey)

        // Request signature from the SSH agent
        let signatureData = try await agent.requestSignature(for: data, usingKey: agentKey, flags: flags)

        // For RSA keys, we need to ensure the signature is in the correct format
        if keyType == "ssh-rsa" && flags.contains(.rsaSha2_256) {
            // For RSA with SHA-256, we need to prepend the algorithm identifier
            // Format: [string "rsa-sha2-256"][string signature]
            var rsaSignature = Data()
            let algorithmName = "rsa-sha2-256"
            var algorithmNameLength = UInt32(algorithmName.utf8.count).bigEndian

            withUnsafeBytes(of: &algorithmNameLength) { ptr in
                rsaSignature.append(ptr.bindMemory(to: UInt8.self))
            }
            rsaSignature.append(contentsOf: algorithmName.utf8)

            // Add the signature data
            rsaSignature.append(signatureData)
            return rsaSignature
        }

        return signatureData
    }

    /// Determines appropriate signing flags based on the key type.
    ///
    /// This method examines the public key algorithm to determine the most
    /// appropriate signing flags for the SSH agent request. Different key types
    /// may benefit from specific algorithm selections or compatibility modes.
    ///
    /// For RSA keys, the method prefers SHA-256 or SHA-512 hash algorithms over
    /// the legacy SHA-1 for improved security. For other key types, the default
    /// agent behaviour is typically appropriate.
    ///
    /// - Parameter publicKey: The public key to determine flags for
    /// - Returns: Appropriate signing flags for the SSH agent request
    private func determineSigningFlags(for publicKey: NIOSSHPublicKey) -> SSHAgentSignFlags {
        // Use the OpenSSH string representation to determine the key type
        let openSSHString = String(openSSHPublicKey: publicKey)
        let components = openSSHString.split(separator: " ", maxSplits: 1)
        guard let algorithmName = components.first else { return [] }

        switch String(algorithmName) {
        case "ssh-rsa":
            // Prefer SHA-256 for RSA keys for better security
            return .rsaSha2_256
        default:
            // For Ed25519 and ECDSA, use default agent behaviour
            return []
        }
    }
}
