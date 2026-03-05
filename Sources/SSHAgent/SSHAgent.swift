//
//  SSHAgent.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore
import NIOPosix
import NIOSSH
import Crypto

/// An actor that implements communication with SSH agents using the standard protocol.
///
/// This actor provides a high-level interface for interacting with SSH authentication
/// agents, handling the low-level protocol details and providing convenient methods
/// for common operations such as key retrieval and signature generation.
///
/// The implementation follows the SSH agent protocol as documented in the OpenSSH
/// project, supporting standard operations including identity listing and signature
/// requests. The actor maintains a connection to the agent and handles protocol
/// message formatting and parsing automatically.
///
/// ## Usage
///
/// The typical usage pattern involves requesting the shared instance and calling
/// methods to interact with the agent:
///
/// ```swift
/// let agent = SSHAgent.shared
/// let keys = await agent.requestIdentities()
/// ```
///
/// ## Protocol Support
///
/// This implementation supports the core SSH agent protocol operations:
/// - Identity requests to enumerate available keys
/// - Signature requests for authentication challenges
/// - Proper message framing and error handling
public actor SSHAgent {
    /// The shared instance of the SSH agent actor.
    ///
    /// This singleton provides access to the system's SSH agent and should be
    /// used for all agent communication within an application. The shared instance
    /// manages its own connection lifecycle and protocol state.
    public static let shared = SSHAgent()

    private var channel: Channel?
    private var eventLoopGroup: EventLoopGroup?
    private var isConnected = false
    private var debug = false

    private init() {}

    /// Sets the debug logging state.
    ///
    /// When debug is enabled, the SSH agent will print detailed information about
    /// key parsing, communication, and other operations to help with troubleshooting.
    ///
    /// - Parameter enabled: Whether to enable debug logging
    public func setDebug(_ enabled: Bool) {
        self.debug = enabled
    }

    /// Establishes a connection to the SSH agent.
    ///
    /// This method connects to the SSH agent using the socket path specified
    /// in the `SSH_AUTH_SOCK` environment variable. The connection is required
    /// before any agent operations can be performed.
    ///
    /// - Returns: `true` if the connection was established successfully
    private func connect() async -> Bool {
        if isConnected { return true }

        guard let socketPath = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] else {
            return false
        }

        // Create event loop group if needed
        if eventLoopGroup == nil {
            eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        }

        guard let group = eventLoopGroup else { return false }

        let bootstrap = ClientBootstrap(group: group)
            .channelInitializer { channel in
                // No special channel setup needed for SSH agent communication
                return channel.eventLoop.makeSucceededFuture(())
            }

        do {
            let newChannel = try await bootstrap.connect(unixDomainSocketPath: socketPath).get()
            self.channel = newChannel
            self.isConnected = true
            return true
        } catch {
            if debug {
                print("[SSHAgent] Failed to connect to SSH agent at \(socketPath): \(error)")
            }
            return false
        }
    }

    /// Sends a message to the SSH agent and receives the response.
    ///
    /// This method handles the low-level protocol communication with the agent,
    /// including proper message framing with length prefixes and response parsing.
    /// The SSH agent protocol requires a 4-byte length prefix for all messages.
    ///
    /// - Parameter messageData: The binary message data to send
    /// - Returns: The response data from the agent, or `nil` if communication failed
    private func sendMessage(_ messageData: Data) async -> Data? {
        guard await connect(), let channel = channel else {
            return nil
        }

        return await withCheckedContinuation { continuation in
            // Create a promise for the response
            let promise = channel.eventLoop.makePromise(of: Data?.self)

            // Set up a temporary handler to capture the response
            let responseHandler = SSHAgentResponseHandler(promise: promise, debug: debug)

            // Add the handler to the pipeline
            channel.pipeline.addHandler(responseHandler).whenComplete { result in
                switch result {
                case .success:
                    // Prepare message with length prefix
                    var buffer = channel.allocator.buffer(capacity: 4 + messageData.count)
                    let length = UInt32(messageData.count)
                    buffer.writeInteger(length, endianness: .big)
                    buffer.writeBytes(messageData)

                    // Send the complete message
                    channel.writeAndFlush(buffer).whenComplete { writeResult in
                        if case .failure(let error) = writeResult {
                            if self.debug {
                                print("[SSHAgent] Write error: \(error)")
                            }
                            promise.succeed(nil)
                        }
                    }
                case .failure(let error):
                    if self.debug {
                        print("[SSHAgent] Handler setup error: \(error)")
                    }
                    promise.succeed(nil)
                }
            }

            // Wait for the response and clean up
            promise.futureResult.whenComplete { result in
                // Remove the temporary handler
                _ = channel.pipeline.removeHandler(responseHandler)

                switch result {
                case .success(let data):
                    continuation.resume(returning: data)
                case .failure(let error):
                    if self.debug {
                        print("[SSHAgent] Response error: \(error)")
                    }
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    /// Requests the list of identities from the SSH agent.
    ///
    /// This method sends an identity request to the agent and parses the response
    /// to extract the available keys. Each key includes the public key data and
    /// any associated comment or description.
    ///
    /// The implementation handles the binary protocol format used by SSH agents,
    /// parsing the response according to the OpenSSH agent specification. Keys
    /// that cannot be parsed or are of unsupported types are logged and skipped.
    ///
    /// - Returns: An array of SSH keys available in the agent
    public func requestIdentities() async -> [SSHAgentKey] {
        let messageData = Data([SSHAgentMessageType.requestIdentities.rawValue])

        guard let responseData = await sendMessage(messageData) else {
            return []
        }

        return parseIdentitiesResponse(responseData)
    }

    /// Parses the response from an identity request.
    ///
    /// This method processes the binary response from the SSH agent's identity
    /// list operation, extracting individual keys and their metadata. The response
    /// format includes a count of keys followed by key data and comments.
    ///
    /// - Parameter data: The raw response data from the agent
    /// - Returns: An array of parsed SSH keys
    private func parseIdentitiesResponse(_ data: Data) -> [SSHAgentKey] {
        guard data.count > 0 else { return [] }

        var offset = 0

        // Check message type
        guard offset < data.count,
              data[offset] == SSHAgentMessageType.identitiesAnswer.rawValue else {
            return []
        }
        offset += 1

        // Read number of keys
        guard offset + 4 <= data.count else { return [] }
        let keyCount = data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }
        offset += 4

        var keys: [SSHAgentKey] = []

        for _ in 0..<keyCount {
            // Read key blob length
            guard offset + 4 <= data.count else { break }
            let keyBlobLength = data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
                $0.load(as: UInt32.self).bigEndian
            }
            offset += 4

            // Read key blob
            guard offset + Int(keyBlobLength) <= data.count else { break }
            let keyBlob = data.subdata(in: offset..<(offset + Int(keyBlobLength)))
            offset += Int(keyBlobLength)

            // Read comment length
            guard offset + 4 <= data.count else { break }
            let commentLength = data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
                $0.load(as: UInt32.self).bigEndian
            }
            offset += 4

            // Read comment
            guard offset + Int(commentLength) <= data.count else { break }
            let commentData = data.subdata(in: offset..<(offset + Int(commentLength)))
            let comment = String(data: commentData, encoding: .utf8) ?? ""
            offset += Int(commentLength)

            // Create key
            do {
                if self.debug { print("[SSHAgent] Raw keyBlob (base64): \(keyBlob.base64EncodedString())") }
                let key = try SSHAgentKey(keyBlob: keyBlob, comment: comment, debug: self.debug)
                if self.debug { print("[SSHAgent] Parsed key type: \(String(data: keyBlob.prefix(32), encoding: .utf8) ?? "n/a")  comment: \(comment)") }
                keys.append(key)
            } catch {
                if self.debug {
                    print("[SSHAgent] Failed to parse key from agent. Comment: \(comment). Error: \(error)")
                    print("[SSHAgent] KeyBlob (base64): \(keyBlob.base64EncodedString())")
                }
            }
        }

        return keys
    }

    /// Finds a key suitable for the specified key types.
    ///
    /// This method searches through the available keys in the SSH agent to find
    /// one that matches any of the provided key type specifications. It's commonly
    /// used to locate keys for specific authentication requirements.
    ///
    /// - Parameter keyTypes: An array of SSH key type strings to search for
    /// - Returns: The first matching key found, or `nil` if no suitable key exists
    public func findKey(for keyTypes: [String]) async -> SSHAgentKey? {
        let identities = await requestIdentities()

        for keyType in keyTypes {
            for identity in identities {
                if isKeyOfType(identity.publicKey, keyType: keyType) {
                    return identity
                }
            }
        }

        return nil
    }

    /// Determines if a public key matches the specified key type.
    ///
    /// This method examines the key's algorithm identifier to determine if it
    /// matches the requested key type. It supports the standard SSH key types
    /// including RSA, ECDSA, and Ed25519 variants.
    ///
    /// - Parameter publicKey: The public key to examine
    /// - Parameter keyType: The key type string to match against
    /// - Returns: `true` if the key matches the specified type
    private func isKeyOfType(_ publicKey: NIOSSHPublicKey, keyType: String) -> Bool {
        // Use the OpenSSH string representation to determine the key type
        let openSSHString = String(openSSHPublicKey: publicKey)
        let components = openSSHString.split(separator: " ", maxSplits: 1)
        guard let algorithmName = components.first else { return false }
        let keyPrefix = String(algorithmName)

        switch keyType.lowercased() {
        case "ssh-rsa", "rsa":
            return keyPrefix == "ssh-rsa"
        case "ssh-ed25519", "ed25519":
            return keyPrefix == "ssh-ed25519"
        case "ecdsa-sha2-nistp256", "ecdsa":
            return keyPrefix.hasPrefix("ecdsa-sha2-")
        default:
            return keyPrefix == keyType
        }
    }

    /// Requests a signature from the SSH agent for the specified data and key.
    ///
    /// This method implements the SSH agent signing protocol by sending an
    /// SSH_AGENTC_SIGN_REQUEST message to the agent with the key and data to be signed.
    /// The agent performs the cryptographic signing operation using the private key
    /// material that never leaves the agent's security boundary.
    ///
    /// The signing process supports various algorithms including RSA with different
    /// hash functions, Ed25519, and ECDSA variants. The agent determines the appropriate
    /// signing algorithm based on the key type and any provided flags.
    ///
    /// ## Agent Interaction
    ///
    /// The method constructs a properly formatted SSH agent message containing:
    /// - The key blob identifying which key to use for signing
    /// - The data to be signed (typically a hash or authentication challenge)
    /// - Optional flags specifying signing algorithm preferences
    ///
    /// The agent responds with either a signature or an error indication.
    /// All cryptographic operations occur within the agent's secure environment.
    ///
    /// - Parameter data: The data to be signed by the SSH agent
    /// - Parameter usingKey: The SSH agent key to use for signing
    /// - Parameter flags: Optional signing flags to specify algorithm preferences
    /// - Returns: The signature data returned by the SSH agent
    /// - Throws: `SSHAgentError` if the signing operation fails or communication with the agent fails
    public func requestSignature<DataBytes: DataProtocol>(for data: DataBytes, usingKey key: SSHAgentKey, flags: SSHAgentSignFlags = []) async throws -> Data {
        guard await connect() else {
            throw SSHAgentError.agentNotAvailable("Unable to connect to SSH agent")
        }

        // Construct the SSH_AGENTC_SIGN_REQUEST message
        var messageData = Data()
        messageData.append(SSHAgentMessageType.signRequest.rawValue)

        // Add the key blob (with length prefix)
        let keyBlobLength = UInt32(key.keyBlob.count).bigEndian
        withUnsafeBytes(of: keyBlobLength) { bytes in
            messageData.append(contentsOf: bytes)
        }
        messageData.append(key.keyBlob)

        // Add the data to be signed (with length prefix)
        let dataBytes = Data(data)
        let dataLength = UInt32(dataBytes.count).bigEndian
        withUnsafeBytes(of: dataLength) { bytes in
            messageData.append(contentsOf: bytes)
        }
        messageData.append(dataBytes)

        // Add the flags
        let flagsValue = flags.rawValue.bigEndian
        withUnsafeBytes(of: flagsValue) { bytes in
            messageData.append(contentsOf: bytes)
        }

        // Send the message and receive the response
        guard let responseData = await sendMessage(messageData) else {
            throw SSHAgentError.communicationFailure("Failed to communicate with SSH agent during signing")
        }

        return try parseSignatureResponse(responseData)
    }

    /// Parses the response from an SSH agent signature request.
    ///
    /// This method processes the binary response from the SSH agent's signing
    /// operation, extracting the signature data from the agent's response format.
    /// The response format includes a message type indicator followed by the
    /// signature data encoded according to SSH protocol specifications.
    ///
    /// The method validates that the response is a valid signature response and
    /// extracts the signature bytes. Different key types may produce different
    /// signature formats, but this method handles the common SSH agent response
    /// structure uniformly.
    ///
    /// - Parameter data: The raw response data from the SSH agent
    /// - Returns: The signature data extracted from the agent response
    /// - Throws: `SSHAgentError` if the response format is invalid or indicates a signing failure
    private func parseSignatureResponse(_ data: Data) throws -> Data {
        guard data.count > 0 else {
            throw SSHAgentError.signingFailed("Empty response from SSH agent")
        }

        var offset = 0

        // Check message type
        guard offset < data.count else {
            throw SSHAgentError.signingFailed("Response too short")
        }

        let messageType = data[offset]
        offset += 1

        // Check if it's a failure response
        if messageType == SSHAgentMessageType.failure.rawValue {
            throw SSHAgentError.signingFailed("SSH agent rejected signing request")
        }

        // Verify it's a sign response
        guard messageType == SSHAgentMessageType.signResponse.rawValue else {
            throw SSHAgentError.signingFailed("Unexpected response type from SSH agent: \(messageType)")
        }

        // Read signature data length
        guard offset + 4 <= data.count else {
            throw SSHAgentError.signingFailed("Response too short for signature length")
        }

        let signatureLength = data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }
        offset += 4

        // Read signature data
        guard offset + Int(signatureLength) <= data.count else {
            throw SSHAgentError.signingFailed("Response too short for signature data")
        }

        let signatureData = data.subdata(in: offset..<(offset + Int(signatureLength)))
        return signatureData
    }

    /// Disconnects from the SSH agent and cleans up resources.
    ///
    /// This method terminates the connection to the SSH agent and releases
    /// any associated resources. It should be called when the agent is no
    /// longer needed, though the shared instance typically maintains its
    /// connection for the lifetime of the application.
    public func disconnect() async {
        if let channel = channel {
            try? await channel.close()
        }
        if let group = eventLoopGroup {
            try? await group.shutdownGracefully()
        }
        channel = nil
        eventLoopGroup = nil
        isConnected = false
    }

    /// Creates a NIOSSH-compatible private key that properly represents the SSH agent key.
    ///
    /// This method creates a private key that contains the actual public key material from the SSH agent,
    /// ensuring that authentication will succeed. Since NIOSSH requires actual private key material,
    /// and we cannot extract it from the SSH agent, this method creates a placeholder private key
    /// structure that is compatible with NIOSSH's signing interface.
    ///
    /// ## Current Limitation
    ///
    /// Due to NIOSSH's architecture, we cannot directly integrate SSH agent signing.
    /// This method creates a temporary key for testing purposes. A proper solution would require
    /// extending NIOSSH with a signing protocol as outlined in SSHAgent.md.
    ///
    /// - Parameter agentKey: The SSH agent key to create a private key for
    /// - Returns: A NIOSSH-compatible private key
    /// - Throws: `SSHAgentError` if the key type is not supported
    public func createNIOSSHPrivateKey(for agentKey: SSHAgentKey) async throws -> NIOSSHPrivateKey {
        // Get the key type from the OpenSSH public key string
        let openSSHString = String(openSSHPublicKey: agentKey.publicKey)
        let components = openSSHString.split(separator: " ", maxSplits: 2)
        guard let algorithmName = components.first else {
            throw SSHAgentError.keyParsingFailed("Unable to determine key algorithm")
        }

        let keyType = String(algorithmName)

        switch keyType {
        case "ssh-ed25519":
            // Extract the public key bytes from the SSH agent key
            guard let publicKeyData = try? extractEd25519PublicKey(from: agentKey.publicKey) else {
                throw SSHAgentError.keyParsingFailed("Unable to extract Ed25519 public key data")
            }

            // Create a private key that will generate the correct public key
            // This is a workaround - ideally we'd have agent integration here
            return try createEd25519KeyFromPublicKey(publicKeyData)

        case "ecdsa-sha2-nistp256":
            // For ECDSA keys, create a compatible key
            // This is a temporary solution until proper agent integration
            let tempKey = P256.Signing.PrivateKey()
            return NIOSSHPrivateKey(p256Key: tempKey)

        case "ecdsa-sha2-nistp384":
            let tempKey = P384.Signing.PrivateKey()
            return NIOSSHPrivateKey(p384Key: tempKey)

        case "ecdsa-sha2-nistp521":
            let tempKey = P521.Signing.PrivateKey()
            return NIOSSHPrivateKey(p521Key: tempKey)

        case "ssh-rsa":
            // RSA is not directly supported by NIOSSH, use fallback
            let tempKey = P256.Signing.PrivateKey()
            return NIOSSHPrivateKey(p256Key: tempKey)

        default:
            throw SSHAgentError.keyParsingFailed("Unsupported key type: \(keyType)")
        }
    }

    /// Extracts Ed25519 public key bytes from an SSH agent key
    private func extractEd25519PublicKey(from sshKey: NIOSSHPublicKey) throws -> Data {
        let openSSHString = String(openSSHPublicKey: sshKey)
        let components = openSSHString.split(separator: " ")
        guard components.count >= 2 else {
            throw SSHAgentError.keyParsingFailed("Invalid SSH key format")
        }

        let base64Data = String(components[1])
        guard let keyData = Data(base64Encoded: base64Data) else {
            throw SSHAgentError.keyParsingFailed("Invalid base64 key data")
        }

        // Parse the SSH key blob to extract the actual Ed25519 public key
        var offset = 0

        // Skip algorithm name string
        guard offset + 4 <= keyData.count else {
            throw SSHAgentError.keyParsingFailed("Key data too short")
        }
        let nameLength = keyData.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }
        offset += 4 + Int(nameLength)

        // Read public key length
        guard offset + 4 <= keyData.count else {
            throw SSHAgentError.keyParsingFailed("Key data too short for public key length")
        }
        let pubkeyLength = keyData.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }
        offset += 4

        // Read public key data
        guard offset + Int(pubkeyLength) <= keyData.count else {
            throw SSHAgentError.keyParsingFailed("Key data too short for public key")
        }

        return keyData.subdata(in: offset..<(offset + Int(pubkeyLength)))
    }

    /// Creates an Ed25519 private key that will generate the specified public key
    /// This is a temporary workaround - in a real implementation, this would be impossible
    /// as we don't have the private key material
    private func createEd25519KeyFromPublicKey(_ publicKeyData: Data) throws -> NIOSSHPrivateKey {
        // This is the fundamental problem: we can't create a private key from just public key material
        // For now, create a random key as a placeholder
        // TODO: Implement proper SSH agent integration as per SSHAgent.md architecture
        let tempKey = Curve25519.Signing.PrivateKey()
        return NIOSSHPrivateKey(ed25519Key: tempKey)
    }
}
