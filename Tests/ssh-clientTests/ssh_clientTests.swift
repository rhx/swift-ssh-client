import XCTest
import ArgumentParser
@testable import ssh_client

final class ssh_clientTests: XCTestCase {
    func testCommandConfigurationName() {
        XCTAssertEqual(SSHClientCommand.configuration.commandName, "ssh-client")
    }
    
    func testLocalTerminalConfigurationUsesEnvironmentTerm() {
        let configuration = LocalTerminalConfiguration.current(environment: ["TERM": "screen-256color"])

        XCTAssertEqual(configuration.term, "screen-256color")
    }

    func testConnectionClosedMessageMatchesSSHStyle() {
        XCTAssertEqual(
            connectionClosedMessage(host: "example.com"),
            "Connection to example.com closed."
        )
    }

    func testLocalTerminalModeRestoreUsesBackupDescriptors() {
        var setAttributesCalls: [(Int32, Int32)] = []
        var setFlagsCalls: [(Int32, Int32, Int32)] = []
        var closeCalls: [Int32] = []

        let mode = LocalTerminalMode(
            restoreInputFileDescriptor: 41,
            restoreOutputFileDescriptor: 42,
            inputFlags: 0x101,
            outputFlags: 0x202,
            setAttributes: { fileDescriptor, action, attributes in
                _ = attributes.pointee
                setAttributesCalls.append((fileDescriptor, action))
                return 0
            },
            setFlags: { fileDescriptor, command, flags in
                setFlagsCalls.append((fileDescriptor, command, flags))
                return 0
            },
            closeDescriptor: { fileDescriptor in
                closeCalls.append(fileDescriptor)
                return 0
            }
        )

        mode.restore()

        XCTAssertEqual(setAttributesCalls.map(\.0), [41])
        XCTAssertEqual(setAttributesCalls.map(\.1), [TCSANOW])
        XCTAssertEqual(setFlagsCalls.count, 2)
        XCTAssertEqual(setFlagsCalls[0].0, 41)
        XCTAssertEqual(setFlagsCalls[0].1, F_SETFL)
        XCTAssertEqual(setFlagsCalls[0].2, 0x101)
        XCTAssertEqual(setFlagsCalls[1].0, 42)
        XCTAssertEqual(setFlagsCalls[1].1, F_SETFL)
        XCTAssertEqual(setFlagsCalls[1].2, 0x202)
        XCTAssertEqual(closeCalls, [41, 42])
    }

    func testCommandParsesWithoutRemoteCommand() throws {
        let command = try SSHClientCommand.parseAsRoot(["example.com"]) as? SSHClientCommand

        XCTAssertEqual(command?.destination, "example.com")
        XCTAssertEqual(command?.command, [])
        XCTAssertEqual(command?.listen, [])
    }

    func testCommandParsesMultipleListenOptions() throws {
        let command = try SSHClientCommand.parseAsRoot([
            "-L", "8080:web.internal:80",
            "-L", "2222:127.0.0.1:22",
            "example.com",
        ]) as? SSHClientCommand

        XCTAssertEqual(command?.destination, "example.com")
        XCTAssertEqual(command?.command, [])
        XCTAssertEqual(command?.listen, [
            "8080:web.internal:80",
            "2222:127.0.0.1:22",
        ])
    }

    func testCommandParsesRemoteCommandAfterListenOptions() throws {
        let command = try SSHClientCommand.parseAsRoot([
            "-L", "8080:web.internal:80",
            "example.com",
            "uname",
            "-a",
        ]) as? SSHClientCommand

        XCTAssertEqual(command?.destination, "example.com")
        XCTAssertEqual(command?.listen, ["8080:web.internal:80"])
        XCTAssertEqual(command?.command, ["uname", "-a"])
    }
}
