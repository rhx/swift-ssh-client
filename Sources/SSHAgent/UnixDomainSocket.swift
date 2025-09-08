//
//  UnixDomainSocket.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation

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
public actor UnixDomainSocket {
    private var fileDescriptor: Int32?
    private let socketPath: String

    /// Creates a new Unix domain socket for the specified path.
    ///
    /// This initialiser prepares the socket for connection to an SSH agent
    /// listening on the provided Unix domain socket path. The actual connection
    /// is established when `connect()` is called.
    ///
    /// - Parameter path: The filesystem path to the Unix domain socket
    public init(path: String) {
        self.socketPath = path
    }

    /// Establishes a connection to the SSH agent socket.
    ///
    /// This method creates a Unix domain socket and attempts to connect to
    /// the SSH agent at the configured path. The connection must be established
    /// before any communication with the agent can occur.
    ///
    /// - Returns: `true` if the connection was successful, `false` otherwise
    public func connect() -> Bool {
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
    public func send(_ data: Data) -> Bool {
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
    public func receive(count: Int) -> Data? {
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
    public func disconnect() {
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
