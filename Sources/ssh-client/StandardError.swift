//
//  StandardError.swift
//
//  Copyright 2026 Rene Hexel. All rights reserved.
//
import Foundation

func connectionClosedMessage(host: String) -> String {
    "Connection to \(host) closed."
}

func writeStandardError(_ message: String) {
    FileHandle.standardError.write(Data(message.utf8))
}

func writeStandardErrorLine(_ message: String) {
    writeStandardError(message + "\n")
}

func writeConnectionClosedLine(host: String) {
    writeStandardErrorLine(connectionClosedMessage(host: host))
}
