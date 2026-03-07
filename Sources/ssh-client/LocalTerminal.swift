//
//  LocalTerminal.swift
//
//  Copyright 2026 Rene Hexel. All rights reserved.
//
import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

struct LocalTerminalConfiguration {
    let term: String
    let columns: Int
    let rows: Int

    static func current(environment: [String: String] = ProcessInfo.processInfo.environment) -> LocalTerminalConfiguration {
        let term = environment["TERM"] ?? "xterm-256color"
        let size = Self.currentSize()
        return LocalTerminalConfiguration(term: term, columns: size.columns, rows: size.rows)
    }

    static func currentSize() -> (columns: Int, rows: Int) {
        var windowSize = winsize()
        if ioctl(STDIN_FILENO, UInt(TIOCGWINSZ), &windowSize) == 0 {
            let columns = max(Int(windowSize.ws_col), 80)
            let rows = max(Int(windowSize.ws_row), 24)
            return (columns, rows)
        }
        return (80, 24)
    }
}

struct LocalTerminalMode {
    typealias SetAttributes = (Int32, Int32, UnsafeMutablePointer<termios>) -> Int32
    typealias SetFlags = (Int32, Int32, Int32) -> Int32
    typealias CloseDescriptor = (Int32) -> Int32

    private let originalAttributes: termios
    private let restoreInputFileDescriptor: Int32?
    private let restoreOutputFileDescriptor: Int32?
    private let inputFlags: Int32?
    private let outputFlags: Int32?
    private let setAttributes: SetAttributes
    private let setFlags: SetFlags
    private let closeDescriptor: CloseDescriptor

    init() throws {
        guard isatty(STDIN_FILENO) == 1 else {
            self.originalAttributes = termios()
            self.restoreInputFileDescriptor = nil
            self.restoreOutputFileDescriptor = nil
            self.inputFlags = nil
            self.outputFlags = nil
            self.setAttributes = Self.liveSetAttributes
            self.setFlags = Self.liveSetFlags
            self.closeDescriptor = Self.liveClose
            return
        }

        let restoreInputFileDescriptor = dup(STDIN_FILENO)
        guard restoreInputFileDescriptor >= 0 else {
            throw POSIXError(.EBADF)
        }

        let restoreOutputFileDescriptor = dup(STDOUT_FILENO)
        guard restoreOutputFileDescriptor >= 0 else {
            _ = close(restoreInputFileDescriptor)
            throw POSIXError(.EBADF)
        }

        var attributes = termios()
        guard tcgetattr(restoreInputFileDescriptor, &attributes) == 0 else {
            _ = close(restoreInputFileDescriptor)
            _ = close(restoreOutputFileDescriptor)
            throw POSIXError(.ENOTTY)
        }

        self.originalAttributes = attributes
        self.restoreInputFileDescriptor = restoreInputFileDescriptor
        self.restoreOutputFileDescriptor = restoreOutputFileDescriptor
        self.inputFlags = Self.currentFlags(for: restoreInputFileDescriptor)
        self.outputFlags = Self.currentFlags(for: restoreOutputFileDescriptor)
        self.setAttributes = Self.liveSetAttributes
        self.setFlags = Self.liveSetFlags
        self.closeDescriptor = Self.liveClose

        var rawAttributes = attributes
        #if canImport(Darwin)
        cfmakeraw(&rawAttributes)
        #elseif canImport(Glibc)
        cfmakeraw(&rawAttributes)
        #endif

        rawAttributes.c_oflag |= tcflag_t(OPOST)
        guard tcsetattr(STDIN_FILENO, TCSANOW, &rawAttributes) == 0 else {
            throw POSIXError(.ENOTTY)
        }
    }

    init(
        originalAttributes: termios = termios(),
        restoreInputFileDescriptor: Int32?,
        restoreOutputFileDescriptor: Int32?,
        inputFlags: Int32?,
        outputFlags: Int32?,
        setAttributes: @escaping SetAttributes,
        setFlags: @escaping SetFlags,
        closeDescriptor: @escaping CloseDescriptor
    ) {
        self.originalAttributes = originalAttributes
        self.restoreInputFileDescriptor = restoreInputFileDescriptor
        self.restoreOutputFileDescriptor = restoreOutputFileDescriptor
        self.inputFlags = inputFlags
        self.outputFlags = outputFlags
        self.setAttributes = setAttributes
        self.setFlags = setFlags
        self.closeDescriptor = closeDescriptor
    }

    func restore() {
        guard let restoreInputFileDescriptor, let restoreOutputFileDescriptor else {
            return
        }
        var attributes = originalAttributes
        _ = setAttributes(restoreInputFileDescriptor, TCSANOW, &attributes)
        Self.restore(flags: inputFlags, for: restoreInputFileDescriptor, setFlags: setFlags)
        Self.restore(flags: outputFlags, for: restoreOutputFileDescriptor, setFlags: setFlags)
        _ = closeDescriptor(restoreInputFileDescriptor)
        _ = closeDescriptor(restoreOutputFileDescriptor)
    }

    private static func currentFlags(for fileDescriptor: Int32) -> Int32? {
        let flags = fcntl(fileDescriptor, F_GETFL)
        return flags >= 0 ? flags : nil
    }

    private static func restore(
        flags: Int32?,
        for fileDescriptor: Int32,
        setFlags: SetFlags
    ) {
        guard let flags else {
            return
        }
        _ = setFlags(fileDescriptor, F_SETFL, flags)
    }

    private static func liveSetAttributes(
        fileDescriptor: Int32,
        action: Int32,
        attributes: UnsafeMutablePointer<termios>
    ) -> Int32 {
        tcsetattr(fileDescriptor, action, attributes)
    }

    private static func liveSetFlags(
        fileDescriptor: Int32,
        command: Int32,
        flags: Int32
    ) -> Int32 {
        fcntl(fileDescriptor, command, flags)
    }

    private static func liveClose(fileDescriptor: Int32) -> Int32 {
        close(fileDescriptor)
    }
}
