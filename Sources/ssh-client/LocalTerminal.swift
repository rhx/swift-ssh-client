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

/// Local terminal description used for a pseudo-terminal request.
///
/// The CLI reads the current terminal type and size before opening an interactive
/// shell so the remote side can configure line editing, screen width, and similar
/// terminal-sensitive behaviour correctly.
struct LocalTerminalConfiguration {
    /// Terminal type from the local process environment.
    let term: String

    /// Current terminal width in character cells.
    let columns: Int

    /// Current terminal height in character cells.
    let rows: Int

    /// Read the current terminal settings from the process environment and stdin.
    ///
    /// The command-line client uses this snapshot to populate the pseudo-terminal
    /// request that starts an interactive remote shell. When a value cannot be
    /// detected locally, the method falls back to conservative defaults.
    ///
    /// - Parameter environment: The environment dictionary to inspect for `TERM`.
    /// - Returns: The best available terminal description for the current process.
    static func current(environment: [String: String] = ProcessInfo.processInfo.environment) -> LocalTerminalConfiguration {
        let term = environment["TERM"] ?? "xterm-256color"
        let size = Self.currentSize()
        return LocalTerminalConfiguration(term: term, columns: size.columns, rows: size.rows)
    }

    /// Read the current terminal size.
    ///
    /// If the size cannot be queried, the method falls back to a conservative
    /// default of `80x24`.
    ///
    /// - Returns: The terminal width and height in character cells.
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

/// Local terminal mode for an interactive SSH session.
///
/// The type duplicates the original terminal file descriptors before changing
/// the current process state. That allows it to restore both terminal attributes
/// and file status flags even if the interactive shell bootstrap has modified the
/// inherited standard descriptors.
struct LocalTerminalMode {
    /// Terminal attribute restoration function for a file descriptor.
    typealias SetAttributes = (Int32, Int32, UnsafeMutablePointer<termios>) -> Int32

    /// File-status restoration function for a file descriptor.
    typealias SetFlags = (Int32, Int32, Int32) -> Int32

    /// Close function for a duplicated file descriptor.
    typealias CloseDescriptor = (Int32) -> Int32

    /// Terminal attributes captured before raw mode was enabled.
    private let originalAttributes: termios

    /// Duplicate of stdin used during restoration.
    private let restoreInputFileDescriptor: Int32?

    /// Duplicate of stdout used during restoration.
    private let restoreOutputFileDescriptor: Int32?

    /// Original file status flags for the duplicated stdin descriptor.
    private let inputFlags: Int32?

    /// Original file status flags for the duplicated stdout descriptor.
    private let outputFlags: Int32?

    /// Attribute restoration operation used by `restore()`.
    private let setAttributes: SetAttributes

    /// File-status restoration operation used by `restore()`.
    private let setFlags: SetFlags

    /// Close operation used when duplicated descriptors are no longer needed.
    private let closeDescriptor: CloseDescriptor

    /// Capture the current terminal state and switch stdin into raw mode.
    ///
    /// The initialiser duplicates the local terminal descriptors before changing
    /// any settings. Those duplicates provide a stable source of terminal
    /// attributes and file status flags during restoration, even if the active
    /// standard descriptors are modified by the interactive session bootstrap.
    ///
    /// - Throws: `POSIXError` if the terminal cannot be duplicated or configured.
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

    /// Create a terminal mode with injected restoration operations for tests.
    ///
    /// Tests use this initialiser to verify restoration behaviour without
    /// depending on a live terminal device or mutating the process terminal state.
    ///
    /// - Parameters:
    ///   - originalAttributes: The attributes to restore.
    ///   - restoreInputFileDescriptor: The duplicated stdin descriptor.
    ///   - restoreOutputFileDescriptor: The duplicated stdout descriptor.
    ///   - inputFlags: The original stdin status flags.
    ///   - outputFlags: The original stdout status flags.
    ///   - setAttributes: The attribute restoration operation.
    ///   - setFlags: The file-status restoration operation.
    ///   - closeDescriptor: The close operation for duplicated descriptors.
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

    /// Restore the local terminal state captured by the initialiser.
    ///
    /// The method uses the duplicated descriptors rather than assuming that the
    /// inherited `stdin` or `stdout` descriptors are still in their original state.
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

    /// Read the file status flags for a descriptor.
    ///
    /// The returned flags are later replayed during restoration so the caller can
    /// undo changes such as non-blocking mode introduced by session setup code.
    ///
    /// - Parameter fileDescriptor: The descriptor to inspect.
    /// - Returns: The current flags, or `nil` if they cannot be read.
    private static func currentFlags(for fileDescriptor: Int32) -> Int32? {
        let flags = fcntl(fileDescriptor, F_GETFL)
        return flags >= 0 ? flags : nil
    }

    /// Restore file status flags for a descriptor when a saved value exists.
    ///
    /// This helper is a no-op when no saved flag value is available, which keeps
    /// restoration tolerant of descriptors whose flags could not be read earlier.
    ///
    /// - Parameters:
    ///   - flags: The saved flags to restore.
    ///   - fileDescriptor: The descriptor to update.
    ///   - setFlags: The operation that applies the saved flags.
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

    /// Call the platform `tcsetattr` function.
    ///
    /// The wrapper keeps the production implementation injectable so tests can
    /// assert restoration behaviour without touching the real terminal.
    ///
    /// - Parameters:
    ///   - fileDescriptor: The descriptor whose attributes should be restored.
    ///   - action: The `tcsetattr` action.
    ///   - attributes: The attributes to apply.
    /// - Returns: The return code from `tcsetattr`.
    private static func liveSetAttributes(
        fileDescriptor: Int32,
        action: Int32,
        attributes: UnsafeMutablePointer<termios>
    ) -> Int32 {
        tcsetattr(fileDescriptor, action, attributes)
    }

    /// Call the platform `fcntl` function to set file status flags.
    ///
    /// The wrapper exists for the same reason as `liveSetAttributes`: it keeps
    /// the side-effecting system call replaceable during tests.
    ///
    /// - Parameters:
    ///   - fileDescriptor: The descriptor to update.
    ///   - command: The `fcntl` command.
    ///   - flags: The flags to apply.
    /// - Returns: The return code from `fcntl`.
    private static func liveSetFlags(
        fileDescriptor: Int32,
        command: Int32,
        flags: Int32
    ) -> Int32 {
        fcntl(fileDescriptor, command, flags)
    }

    /// Close a duplicated descriptor.
    ///
    /// Test code replaces this closure so it can observe descriptor lifetimes
    /// without closing real process file descriptors.
    ///
    /// - Parameter fileDescriptor: The descriptor to close.
    /// - Returns: The return code from `close`.
    private static func liveClose(fileDescriptor: Int32) -> Int32 {
        close(fileDescriptor)
    }
}
