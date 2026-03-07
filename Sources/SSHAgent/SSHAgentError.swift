//
//  SSHAgentError.swift
//
//  Copyright © 2022, 2025 Rene Hexel. All rights reserved.
//  Created by Rene Hexel on 12/5/2022.
//
import Foundation

/// Errors raised whilst communicating with an SSH agent.
///
/// `SSHAgentError` captures failures in socket access, response parsing, key
/// decoding, and agent-backed signing operations. The associated strings retain
/// the lower-level detail needed for diagnostics without exposing transport
/// internals as separate public types.
public enum SSHAgentError: Error {
    case invalidKeyData(String)
    case communicationFailure(String)
    case keyParsingFailed(String)
    case signingFailed(String)
    case agentNotAvailable(String)
}
