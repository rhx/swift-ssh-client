//
//  StandardError.swift
//
//  Copyright 2026 Rene Hexel. All rights reserved.
//
import Foundation

/// Build the trailing status line printed after an interactive shell closes.
///
/// The returned string matches the format used by the OpenSSH client so that the
/// command-line tool behaves predictably when a session ends.
///
/// - Parameter host: The remote host name that the client connected to.
/// - Returns: The formatted status line without a trailing newline.
func connectionClosedMessage(host: String) -> String {
    "Connection to \(host) closed."
}

/// Write text to standard error without appending a trailing newline.
///
/// The helper centralises standard-error output so the CLI can avoid direct use
/// of `stderr` APIs that trigger stricter concurrency checks on some toolchains.
///
/// - Parameter message: The text to write.
func writeStandardError(_ message: String) {
    FileHandle.standardError.write(Data(message.utf8))
}

/// Write a line to standard error.
///
/// The function appends a newline before delegating to `writeStandardError(_:)`
/// so the CLI can consistently emit line-oriented status and error messages.
///
/// - Parameter message: The text to write before the newline.
func writeStandardErrorLine(_ message: String) {
    writeStandardError(message + "\n")
}

/// Write the SSH-style connection-closed line for a host.
///
/// Interactive sessions call this helper after the remote shell exits so local
/// behaviour matches the conventional `ssh` command-line experience.
///
/// - Parameter host: The remote host name that has just disconnected.
func writeConnectionClosedLine(host: String) {
    writeStandardErrorLine(connectionClosedMessage(host: host))
}
