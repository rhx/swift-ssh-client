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
    private let originalAttributes: termios
    private let enabled: Bool

    init() throws {
        guard isatty(STDIN_FILENO) == 1 else {
            self.originalAttributes = termios()
            self.enabled = false
            return
        }

        var attributes = termios()
        guard tcgetattr(STDIN_FILENO, &attributes) == 0 else {
            throw POSIXError(.ENOTTY)
        }

        self.originalAttributes = attributes
        self.enabled = true

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

    func restore() {
        guard enabled else {
            return
        }
        var attributes = originalAttributes
        _ = tcsetattr(STDIN_FILENO, TCSANOW, &attributes)
    }
}
