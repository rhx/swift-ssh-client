//
//  SSHAgentError.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation

/// Errors that can occur during SSH agent communication.
public enum SSHAgentError: Error {
    case invalidKeyData(String)
    case communicationFailure(String)
    case keyParsingFailed(String)
    case signingFailed(String)
    case agentNotAvailable(String)
}
