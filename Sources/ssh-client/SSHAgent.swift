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

/// SSH Agent protocol message types as defined in OpenSSH
enum SSHAgentMessageType: UInt8 {
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case failure = 5
    case success = 6
}

/// Errors that can occur during SSH agent communication.
enum SSHAgentError: Error {
    case invalidKeyData(String)
    case communicationFailure(String)
    case keyParsingFailed(String)
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
    /// - Throws: `NIOSSHError` if the key cannot be parsed or is of an unsupported type
    public init(keyBlob: Data, comment: String) throws {
        self.keyBlob = keyBlob
        self.comment = comment
        
        // Convert the binary key blob to OpenSSH public key format
        let openSSHString = try Self.convertKeyBlobToOpenSSHFormat(keyBlob)
        self.publicKey = try NIOSSHPublicKey(openSSHPublicKey: openSSHString)
    }
    
    /// Converts a binary key blob to OpenSSH public key string format.
    /// 
    /// This method parses the SSH wire format key blob and converts it to the
    /// standard OpenSSH public key string format that can be parsed by NIOSSH.
    /// 
    /// - Parameter keyBlob: The binary key data from the SSH agent
    /// - Returns: An OpenSSH format public key string
    /// - Throws: `SSHAgentError` if the key format is not recognised or supported
    private static func convertKeyBlobToOpenSSHFormat(_ keyBlob: Data) throws -> String {
        var offset = 0
        
        // Read the key type (algorithm name)
        guard offset + 4 <= keyBlob.count else {
            throw SSHAgentError.invalidKeyData("Key blob too short for algorithm name length")
        }
        
        let algorithmNameLength = keyBlob.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }
        offset += 4
        
        guard offset + Int(algorithmNameLength) <= keyBlob.count else {
            throw SSHAgentError.invalidKeyData("Key blob too short for algorithm name")
        }
        
        let algorithmNameData = keyBlob.subdata(in: offset..<(offset + Int(algorithmNameLength)))
        guard let algorithmName = String(data: algorithmNameData, encoding: .utf8) else {
            throw SSHAgentError.invalidKeyData("Invalid algorithm name encoding")
        }
        
        // Convert the entire key blob to base64
        let base64KeyData = keyBlob.base64EncodedString()
        
        // Return the OpenSSH format: "algorithm base64-key"
        return "\(algorithmName) \(base64KeyData)"
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
    
    private init() {}
    
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
                let key = try SSHAgentKey(keyBlob: keyBlob, comment: comment)
                keys.append(key)
            } catch {
                print("Warning: Failed to parse key from agent: \(error)")
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
}