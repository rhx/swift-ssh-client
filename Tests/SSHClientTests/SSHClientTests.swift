import XCTest
@testable import SSHClient
import NIOCore
import NIOEmbedded
import NIOSSH

final class SSHClientTests: XCTestCase {
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
}
