//
//  SSHAgentMessageType.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation

/// SSH agent protocol message identifiers used on the wire.
///
/// The cases map directly to the numeric message tags defined by the OpenSSH
/// agent protocol. They are used when encoding requests and validating replies
/// received from the local SSH agent socket.
public enum SSHAgentMessageType: UInt8 {
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case failure = 5
    case success = 6
}
