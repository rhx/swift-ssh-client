//
//  SSHAgentSignFlags.swift
//
//  Copyright © 2022, 2025, 2026 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation

/// SSH agent signing flags defined by the OpenSSH agent protocol.
///
/// These flags let the client request a specific signature algorithm when the
/// agent supports more than one variant for the same key type. The RSA-specific
/// flags are used to prefer SHA-2 based signatures over legacy RSA behaviour.
public struct SSHAgentSignFlags: OptionSet, Sendable {
    public let rawValue: UInt32

    /// Create a flag set from the raw protocol bit pattern.
    ///
    /// The raw value matches the unsigned 32-bit field used in SSH agent signing
    /// requests.
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Flag requesting the RSA SHA-256 signature algorithm.
    public static let rsaSha2_256 = SSHAgentSignFlags(rawValue: 0x02)

    /// Flag requesting the RSA SHA-512 signature algorithm.
    public static let rsaSha2_512 = SSHAgentSignFlags(rawValue: 0x04)
}
