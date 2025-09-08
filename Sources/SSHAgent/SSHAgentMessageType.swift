//
//  SSHAgentMessageType.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation

/// SSH Agent protocol message types as defined in OpenSSH
public enum SSHAgentMessageType: UInt8 {
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case failure = 5
    case success = 6
}