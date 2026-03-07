//
//  SSHAgentSignFlags.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation

/// Signing flags recognised by the SSH agent protocol.
///
/// These option bits let the client request a specific signature algorithm when
/// the agent supports multiple variants for the same key type. The RSA-related
/// flags are used to prefer SHA-2 signatures over legacy RSA behaviour.
public struct SSHAgentSignFlags: OptionSet, Sendable {
    public let rawValue: UInt32

    /// Create a set of SSH agent flags from a raw protocol bit pattern.
    ///
    /// - Parameter rawValue: Raw unsigned 32-bit flag value used on the wire.
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Flag requesting the RSA SHA-256 signature algorithm.
    public static let rsaSha2_256 = SSHAgentSignFlags(rawValue: 0x02)

    /// Flag requesting the RSA SHA-512 signature algorithm.
    public static let rsaSha2_512 = SSHAgentSignFlags(rawValue: 0x04)
}
