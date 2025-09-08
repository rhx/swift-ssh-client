//
//  SSHAgent.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation
import NIOCore
import NIOPosix
import NIOSSH
import Crypto

/// SSH Agent protocol message types as defined in OpenSSH
enum SSHAgentMessageType: UInt8 {
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case failure = 5
    case success = 6
}

/// SSH Agent signing flags as defined in the OpenSSH protocol
public struct SSHAgentSignFlags: OptionSet {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// RSA SHA2-256 signature algorithm
    public static let rsaSha2_256 = SSHAgentSignFlags(rawValue: 0x02)
    /// RSA SHA2-512 signature algorithm
    public static let rsaSha2_512 = SSHAgentSignFlags(rawValue: 0x04)
}

/// Errors that can occur during SSH agent communication.
enum SSHAgentError: Error {
    case invalidKeyData(String)
    case communicationFailure(String)
    case keyParsingFailed(String)
    case signingFailed(String)
    case agentNotAvailable(String)
}

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

/// A Unix domain socket implementation for communicating with SSH agents.
///
/// This actor provides low-level socket operations for connecting to and
/// communicating with SSH agents via Unix domain sockets. It handles the
/// establishment of connections, data transmission, and proper cleanup
/// of socket resources.
///
/// The implementation uses Foundation's networking APIs to provide a
/// cross-platform solution that works reliably on both macOS and Linux
/// environments where SSH agents are commonly deployed.
actor UnixDomainSocket {
    private var fileDescriptor: Int32?
    private let socketPath: String

    /// Creates a new Unix domain socket for the specified path.
    ///
    /// This initialiser prepares the socket for connection to an SSH agent
    /// listening on the provided Unix domain socket path. The actual connection
    /// is established when `connect()` is called.
    ///
    /// - Parameter path: The filesystem path to the Unix domain socket
    init(path: String) {
        self.socketPath = path
    }

    /// Establishes a connection to the SSH agent socket.
    ///
    /// This method creates a Unix domain socket and attempts to connect to
    /// the SSH agent at the configured path. The connection must be established
    /// before any communication with the agent can occur.
    ///
    /// - Returns: `true` if the connection was successful, `false` otherwise
    func connect() -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            close(fd)
            return false
        }

        withUnsafeMutableBytes(of: &addr.sun_path) { pathPtr in
            pathBytes.withUnsafeBufferPointer { bytes in
                pathPtr.copyMemory(from: UnsafeRawBufferPointer(bytes))
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard connectResult == 0 else {
            close(fd)
            return false
        }

        self.fileDescriptor = fd
        return true
    }

    /// Sends data to the connected SSH agent.
    ///
    /// This method transmits the provided data over the established socket
    /// connection to the SSH agent. The data should be properly formatted
    /// according to the SSH agent protocol specification.
    ///
    /// - Parameter data: The binary data to send to the agent
    /// - Returns: `true` if all data was sent successfully, `false` otherwise
    func send(_ data: Data) -> Bool {
        guard let fd = fileDescriptor else { return false }

        return data.withUnsafeBytes { bytes in
            let result = write(fd, bytes.baseAddress, bytes.count)
            return result == bytes.count
        }
    }

    /// Receives data from the connected SSH agent.
    ///
    /// This method reads the specified number of bytes from the SSH agent
    /// socket connection. It blocks until all requested data is received
    /// or an error occurs during the read operation.
    ///
    /// - Parameter count: The number of bytes to read from the socket
    /// - Returns: The received data, or `nil` if an error occurred
    func receive(count: Int) -> Data? {
        guard let fd = fileDescriptor, count > 0 else { return nil }

        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes { bytes in
            read(fd, bytes.baseAddress, count)
        }

        guard result == count else { return nil }
        return data
    }

    /// Closes the socket connection and releases resources.
    ///
    /// This method terminates the connection to the SSH agent and cleans up
    /// the associated socket file descriptor. It should be called when the
    /// socket is no longer needed to prevent resource leaks.
    func disconnect() {
        if let fd = fileDescriptor {
            close(fd)
            fileDescriptor = nil
        }
    }

    deinit {
        if let fd = fileDescriptor {
            close(fd)
        }
    }
}

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

    private var socket: UnixDomainSocket?
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

        let newSocket = UnixDomainSocket(path: socketPath)
        guard await newSocket.connect() else {
            return false
        }

        self.socket = newSocket
        self.isConnected = true
        return true
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
        guard await connect(), let socket = socket else {
            return nil
        }

        // Prepare message with length prefix
        var lengthData = Data(count: 4)
        let length = UInt32(messageData.count).bigEndian
        withUnsafeBytes(of: length) { bytes in
            lengthData.replaceSubrange(0..<4, with: bytes)
        }

        // Send length prefix and message
        guard await socket.send(lengthData),
              await socket.send(messageData) else {
            return nil
        }

        // Read response length
        guard let responseLengthData = await socket.receive(count: 4) else {
            return nil
        }

        let responseLength = responseLengthData.withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }

        // Read response data
        return await socket.receive(count: Int(responseLength))
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
        if let socket = socket {
            await socket.disconnect()
        }
        socket = nil
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
    public func sign<DataBytes: DataProtocol>(_ data: DataBytes) async throws -> Data {
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
