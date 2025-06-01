//
// Created by Rene Hexel on 12/5/2022.
//
import Foundation

/// An actor that implements the ssh-agent protocol.
public actor SSHAgent {
    /// The shared instance of the ssh-agent actor.
    /// This is the only instance that should be used.
    /// It is created on demand.
    /// - Note: This is a singleton.
    /// - Note: This is a lazy static variable.
    public static var shared: SSHAgent = {
        return SSHAgent()
    }()

    /// The ssh-agent socket.
    var agentSocket: Socket?

    /// Valid states for the ssh-agent protocol
    enum State {
        case noSocket
        case disconnected
        case connected
    }
    var state = State.noSocket

    /// Get the ssh-agent socket.
    /// - Returns: `true` if the socket name is found in the ssh-agent environment variables.
    func setupAgentSocket() -> Bool {
        // Get the socket name from SSH_AUTH_SOCK
        let sshAuthSock = getenv("SSH_AUTH_SOCK").map { String(cString: $0) } ?? "/tmp/ssh-agent"
        // Connect to the ssh-agent socket
        guard let agentSocket = Socket(path: sshAuthSock) else {
            return false
        }
        self.agentSocket = agentSocket
        return true
    }

    /// Connect to the ssh-agent socket.
    /// - Returns: `true` if the socket is connected.
    func connect() -> Bool {
        guard let agentSocket = agentSocket else {
            return false
        }
        guard agentSocket.isConnected || agentSocket.connect() else {
            return false
        }
        state = .connected
        return true
    }
    /// Find a key in the ssh-agent
    /// - Parameter keyType: The key type to find
    /// - Returns: The key if found, nil otherwise
    /// - Note: This is a blocking call.
    /// - Note: This is a synchronous call.
    func findKey(for keyType: String) -> Key? {
        // Check if the ssh-agent is connected
        if state != .connected {
            guard state != .noSocket || setupAgentSocket() else {
                return nil
            }
            guard connect() else {
                return nil
            }
        }
        // Send the request to the ssh-agent
        let request = "LOOKUP \(keyType)\n"
        let requestData = request.data(using: .utf8)!
        agentSocket.write(requestData)
        // Read the response
        guard let response = agentSocket.readString(length: 1024) else {
            return nil
        }
        // Check if the key was found
        if response.hasPrefix("OK") {
            // Get the key data
            let keyData = response.dropFirst(3)
            // Create the key
            let key = Key(data: keyData)
            // Return the key
            return key
        }
    }

    /// Connect to the ssh-agent
    /// - Returns: True if connected, false otherwise
    /// - Note: This is a blocking call.
    /// - Note: This is a synchronous call.
    func connect() -> Bool {
        // Set the socket to no delay
        agentSocket.setNoDelay()
        // Set the socket to no linger
        agentSocket.setNoLinger()
        // Set the socket to no SIGPIPE
        agentSocket.setNoSigpipe()
        //

}