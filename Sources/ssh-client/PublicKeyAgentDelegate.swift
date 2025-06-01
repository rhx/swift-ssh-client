//
//  PublicKeyAgentDelegate.swift
//  
//
//  Created by Rene Hexel on 12/5/2022.
//
import Dispatch
import Foundation
import NIOCore
import NIOSSH

/// A client user auth delegate that provides a public/private key user auth through ssh-agent.
final class PublicKeyAgentDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let queue: DispatchQueue

    init(username: String?, password: String?) {
        queue = DispatchQueue(label: "io.swiftnio.ssh.PublicKeyAgentDelegate")
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        guard availableMethods.contains(.publicKey) else {
            print("Error: public key authentication not supported")
            nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
            return
        }

        queue.async {
            let agent = SSHAgent.shared
            guard let key = agent.findKey(for: "ssh-rsa") ?? agent.findKey(for: "ssh-ed25519") else {
                print("Error: no public key found in ssh-agent")
                nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
                return
            }
            // Get the public key from the agent
            let publicKey = key.publicKey
            // Create a public key authentication challenge
            let challenge = NIOSSHUserAuthenticationChallenge(method: .publicKey, publicKey: publicKey)
            // Return the challenge
            nextChallengePromise.succeed(challenge)
        }
    }
}
