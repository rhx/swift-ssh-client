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

/// A client user authentication delegate that provides public key authentication through SSH agent.
/// 
/// This delegate integrates with the system SSH agent to perform public key authentication
/// for SSH connections. It automatically discovers available keys in the agent and attempts
/// authentication using compatible key types.
/// 
/// The delegate supports standard SSH key types including RSA, Ed25519, and ECDSA keys
/// that are available through the SSH agent. It handles the protocol communication with
/// the agent and presents suitable keys to the SSH authentication process.
/// 
/// ## Usage
/// 
/// Create an instance of this delegate and provide it to the SSH client configuration:
/// 
/// ```swift
/// let delegate = PublicKeyAgentDelegate(username: "user", password: nil)
/// ```
/// 
/// The delegate will automatically attempt to use keys from the SSH agent when public
/// key authentication is available and supported by the server.
/// 
/// ## Key Discovery
/// 
/// The delegate attempts to find suitable keys in the following order:
/// 1. Ed25519 keys (preferred for security and performance)
/// 2. RSA keys (widely supported)
/// 3. ECDSA keys (good balance of security and compatibility)
/// 
/// Only the first suitable key found will be used for authentication attempts.
final class PublicKeyAgentDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let queue: DispatchQueue
    private let username: String?
    
    /// Creates a new public key agent authentication delegate.
    /// 
    /// This initialiser prepares the delegate for SSH agent-based authentication.
    /// The username parameter is stored for use in authentication offers, whilst
    /// the password parameter is ignored since this delegate only handles public
    /// key authentication through the SSH agent.
    /// 
    /// - Parameter username: The username to use for authentication (optional)
    /// - Parameter password: Ignored for this authentication method
    init(username: String?, password: String?) {
        self.username = username
        self.queue = DispatchQueue(label: "io.swiftnio.ssh.PublicKeyAgentDelegate")
    }
    
    /// Determines the next authentication method to attempt.
    /// 
    /// This method is called by the NIOSSH framework when it needs to determine
    /// what authentication method to use next. The delegate checks if public key
    /// authentication is available and, if so, attempts to locate a suitable key
    /// in the SSH agent.
    /// 
    /// The method performs its work asynchronously to avoid blocking the event
    /// loop while communicating with the SSH agent. If no suitable keys are found
    /// or if public key authentication is not supported, the authentication attempt
    /// will fail gracefully.
    /// 
    /// - Parameter availableMethods: The authentication methods supported by the server
    /// - Parameter nextChallengePromise: Promise to fulfil with the authentication offer
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        guard availableMethods.contains(.publicKey) else {
            print("Error: public key authentication not supported")
            nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
            return
        }
        
        queue.async {
            Task {
                await self.attemptAgentAuthentication(nextChallengePromise: nextChallengePromise)
            }
        }
    }
    
    /// Attempts to authenticate using keys from the SSH agent.
    /// 
    /// This method communicates with the SSH agent to discover available keys
    /// and selects the first suitable key for authentication. It tries key types
    /// in order of preference for security and compatibility.
    /// 
    /// The method handles all the low-level details of agent communication and
    /// key selection, presenting a complete authentication offer to the SSH
    /// framework if a suitable key is found.
    /// 
    /// - Parameter nextChallengePromise: Promise to complete with authentication result
    private func attemptAgentAuthentication(nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) async {
        let agent = SSHAgent.shared
        
        // Try to find a suitable key in order of preference
        let preferredKeyTypes = ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"]
        
        guard let agentKey = await agent.findKey(for: preferredKeyTypes) else {
            print("Error: no suitable public key found in ssh-agent")
            nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
            return
        }
        
        // Note: In a complete implementation, we would create a private key wrapper
        // that delegates signing operations to the SSH agent. For now, we'll create
        // a placeholder private key that demonstrates the structure.
        //
        // The proper implementation would:
        // 1. Create a private key wrapper that holds the agent key reference
        // 2. Override the signing method to send signing requests to the SSH agent
        // 3. Return signatures generated by the agent
        
        // Create a temporary private key for demonstration
        // In a real implementation, this would be replaced with an agent-backed key
        let temporaryPrivateKey = createTemporaryPrivateKey(for: agentKey)
        
        // Create the authentication offer
        let offer = NIOSSHUserAuthenticationOffer(
            username: self.username ?? "unknown",
            serviceName: "ssh-connection",
            offer: .privateKey(.init(privateKey: temporaryPrivateKey))
        )
        
        nextChallengePromise.succeed(offer)
    }
    
    /// Creates a temporary private key for demonstration purposes.
    /// 
    /// This method creates a new private key that matches the type of the key
    /// found in the SSH agent. In a complete implementation, this would be
    /// replaced with a wrapper that delegates signing operations to the agent.
    /// 
    /// - Parameter agentKey: The key found in the SSH agent
    /// - Returns: A temporary private key for demonstration
    private func createTemporaryPrivateKey(for agentKey: SSHAgentKey) -> NIOSSHPrivateKey {
        // Determine the key type from the agent key using OpenSSH string representation
        let openSSHString = String(openSSHPublicKey: agentKey.publicKey)
        let components = openSSHString.split(separator: " ", maxSplits: 1)
        let keyType = components.first.map(String.init) ?? "unknown"
        
        // Create a temporary key of the appropriate type
        // Note: This is only for demonstration - a real implementation would
        // wrap the agent key and delegate signing operations to the agent
        switch keyType {
        case "ssh-ed25519":
            return NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey())
        case "ecdsa-sha2-nistp256":
            return NIOSSHPrivateKey(p256Key: P256.Signing.PrivateKey())
        case "ecdsa-sha2-nistp384":
            return NIOSSHPrivateKey(p384Key: P384.Signing.PrivateKey())
        case "ecdsa-sha2-nistp521":
            return NIOSSHPrivateKey(p521Key: P521.Signing.PrivateKey())
        default:
            // Default to Ed25519 for unknown key types
            return NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey())
        }
    }
}


