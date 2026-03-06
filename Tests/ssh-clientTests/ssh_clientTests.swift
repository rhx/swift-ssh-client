import XCTest
@testable import ssh_client

final class ssh_clientTests: XCTestCase {
    func testCommandConfigurationName() {
        XCTAssertEqual(SSHClientCommand.configuration.commandName, "ssh-client")
    }
    
    func testLocalTerminalConfigurationUsesEnvironmentTerm() {
        let configuration = LocalTerminalConfiguration.current(environment: ["TERM": "screen-256color"])

        XCTAssertEqual(configuration.term, "screen-256color")
    }
}
