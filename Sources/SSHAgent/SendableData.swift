//
//  SendableData.swift
//
//  Copyright © 2026 Rene Hexel. All rights reserved.
//
import Foundation

/// A `DataProtocol` value that is also safe to send across concurrency domains.
public typealias SendableData = DataProtocol & Sendable
