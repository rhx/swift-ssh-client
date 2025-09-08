//
//  SSHAgentSignFlags.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation

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