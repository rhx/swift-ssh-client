import Foundation
import NIOCore
import NIOSSH

/// A composite authentication delegate that tries multiple authentication methods in sequence.
///
/// This delegate first attempts SSH agent authentication, and if that fails, falls back to
/// password authentication. This provides the best user experience by automatically trying
/// the most secure method first while maintaining compatibility.
final class CompositeAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let username: String?
    private let password: String?
    private let debug: Bool
    private var attemptedMethods: Set<String> = []

    init(username: String? = nil, password: String? = nil, debug: Bool = false) {
        self.username = username
        self.password = password
        self.debug = debug
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        // Try SSH agent authentication first if available and not yet attempted
        if availableMethods.contains(.publicKey) && !attemptedMethods.contains("publickey") {
            attemptedMethods.insert("publickey")
            if debug { print("[debug] Attempting SSH agent public key authentication...") }

            let agentDelegate = PublicKeyAgentDelegate(username: username, password: password, debug: debug)
            agentDelegate.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
            return
        }

        // Fall back to password authentication if available and not yet attempted
        if availableMethods.contains(.password) && !attemptedMethods.contains("password") {
            attemptedMethods.insert("password")
            if debug { print("[debug] Falling back to password authentication...") }

            let passwordDelegate = InteractivePasswordPromptDelegate(username: username, password: password, debug: debug)
            passwordDelegate.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
            return
        }

        // No more authentication methods to try
        if debug { print("[debug] No more authentication methods available") }
        nextChallengePromise.fail(SSHClientError.publicKeyAuthenticationNotSupported)
    }
}
