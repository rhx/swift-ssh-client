//
//  StandardError.swift
//
//  Copyright 2026 Rene Hexel. All rights reserved.
//
import Foundation

func writeStandardError(_ message: String) {
    FileHandle.standardError.write(Data(message.utf8))
}

func writeStandardErrorLine(_ message: String) {
    writeStandardError(message + "\n")
}
