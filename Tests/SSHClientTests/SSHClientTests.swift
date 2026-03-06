import XCTest
@testable import SSHClient
import NIOCore
import NIOEmbedded
import NIOSSH

final class SSHClientTests: XCTestCase {
    func testPortForwardingConfigurationParsesShortListenSyntax() {
        let configuration = PortForwardingConfiguration.parseListen("8080:example.internal:80")

        XCTAssertEqual(configuration?.bindHost, "localhost")
        XCTAssertEqual(configuration?.bindPort, 8080)
        XCTAssertEqual(configuration?.targetHost, "example.internal")
        XCTAssertEqual(configuration?.targetPort, 80)
    }

    func testPortForwardingConfigurationParsesExplicitBindHost() {
        let configuration = PortForwardingConfiguration.parseListen("127.0.0.1:2222:localhost:22")

        XCTAssertEqual(configuration?.bindHost, "127.0.0.1")
        XCTAssertEqual(configuration?.bindPort, 2222)
        XCTAssertEqual(configuration?.targetHost, "localhost")
        XCTAssertEqual(configuration?.targetPort, 22)
    }

    func testPortForwardingConfigurationRejectsInvalidListenSyntax() {
        XCTAssertNil(PortForwardingConfiguration.parseListen("invalid"))
        XCTAssertNil(PortForwardingConfiguration.parseListen("bind:not-a-port:host:80"))
        XCTAssertNil(PortForwardingConfiguration.parseListen("8080:host:not-a-port"))
    }

    func testBufferingExecHandlerKeepsStdoutAfterExitStatus() throws {
        let channel = EmbeddedChannel()
        let exitStatusPromise = channel.eventLoop.makePromise(of: Int.self)
        let outputPromise = channel.eventLoop.makePromise(of: Data.self)
        let errorOutputPromise = channel.eventLoop.makePromise(of: Data.self)

        try channel.pipeline.addHandler(
            BufferingExecHandler(
                command: "uname -a",
                completePromise: exitStatusPromise,
                outputPromise: outputPromise,
                errorOutputPromise: errorOutputPromise
            )
        ).wait()

        channel.pipeline.fireUserInboundEventTriggered(SSHChannelRequestEvent.ExitStatus(exitStatus: 0))

        var stdout = channel.allocator.buffer(capacity: 32)
        stdout.writeString("Linux test output\n")
        XCTAssertNoThrow(try channel.writeInbound(SSHChannelData(type: .channel, data: .byteBuffer(stdout))))

        try channel.close().wait()

        XCTAssertEqual(try exitStatusPromise.futureResult.wait(), 0)
        XCTAssertEqual(try outputPromise.futureResult.wait(), Data("Linux test output\n".utf8))
        XCTAssertEqual(try errorOutputPromise.futureResult.wait(), Data())
    }

    func testInteractiveShellHandlerCompletesOnChannelInactiveAfterExitStatus() throws {
        let channel = EmbeddedChannel()
        let exitStatusPromise = channel.eventLoop.makePromise(of: Int.self)
        let pseudoTerminalRequest = SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true,
            term: "xterm-256color",
            terminalCharacterWidth: 80,
            terminalRowHeight: 24,
            terminalPixelWidth: 0,
            terminalPixelHeight: 0,
            terminalModes: .init([:])
        )

        try channel.pipeline.addHandler(
            InteractiveShellHandler(
                pseudoTerminalRequest: pseudoTerminalRequest,
                completePromise: exitStatusPromise
            )
        ).wait()

        channel.pipeline.fireUserInboundEventTriggered(SSHChannelRequestEvent.ExitStatus(exitStatus: 0))
        try channel.close().wait()

        XCTAssertEqual(try exitStatusPromise.futureResult.wait(), 0)
    }
}
