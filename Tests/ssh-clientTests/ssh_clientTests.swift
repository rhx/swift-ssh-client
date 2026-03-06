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
