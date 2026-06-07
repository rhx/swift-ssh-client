//
//  SendableData.swift
//
//  Copyright © 2026 Rene Hexel. All rights reserved.
//
import Foundation

/// `DataProtocol` value that is also safe to send across concurrency domains.
///
/// The type alias keeps generic SSH-agent and client data-handling APIs flexible
/// whilst still meeting
/// Swift 6 sendability requirements. Callers can therefore pass `Data` or other
/// sendable `DataProtocol` values without losing the original generic API shape.
public typealias SendableData = DataProtocol & Sendable
