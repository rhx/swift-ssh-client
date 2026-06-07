import XCTest
@testable import SSHClient
import NIOCore
import NIOEmbedded

/// Regression tests for the promise lifecycle in `executeCommand`.
///
/// The original implementation created the exit-status, stdout, and stderr
/// promises up front and only fulfilled them by wiring a channel handler. If
/// channel creation failed first (for example when the connection dropped), the
/// function threw immediately, leaving those promises unfulfilled. NIO's debug
/// build then trapped the process in `EventLoopPromise.deinit`
/// ("leaking an unfulfilled Promise"). These tests pin the contract that every
/// promise is completed on every exit path.
///
/// The assertions are deliberately non-blocking: each promise's future is
/// observed with a `whenComplete` flag and the loop is run once, so a promise
/// that is never completed shows up as a failed assertion rather than a hang.
final class ExecuteCommandPromiseTests: XCTestCase {
    /// On a channel-creation failure, the collector must fail (not leak) all
    /// three result promises and surface the error.
    func testCollectFailsAllPromisesWhenChannelCreationFails() throws {
        let loop = EmbeddedEventLoop()
        defer { try? loop.syncShutdownGracefully() }

        let exitStatus = loop.makePromise(of: Int.self)
        let output = loop.makePromise(of: Data.self)
        let errorOutput = loop.makePromise(of: Data.self)

        // Track completion of each promise without blocking on it.
        var exitDone = false, outputDone = false, errorDone = false
        exitStatus.futureResult.whenComplete { _ in exitDone = true }
        output.futureResult.whenComplete { _ in outputDone = true }
        errorOutput.futureResult.whenComplete { _ in errorDone = true }

        struct Boom: Error {}
        let failedChannelCreation: EventLoopFuture<Channel> = loop.makeFailedFuture(Boom())

        var resultError: Error?
        let result = SSHClient.collectCommandResult(
            channelCreation: failedChannelCreation,
            exitStatusPromise: exitStatus,
            outputPromise: output,
            errorOutputPromise: errorOutput
        )
        result.whenFailure { resultError = $0 }

        loop.run()

        // The collector must surface the channel-creation failure...
        XCTAssertTrue(resultError is Boom, "collector should propagate the channel-creation error")
        // ...and must have completed every result promise, so none leaks at deinit.
        XCTAssertTrue(exitDone, "exit-status promise left unfulfilled (would trap at deinit)")
        XCTAssertTrue(outputDone, "stdout promise left unfulfilled (would trap at deinit)")
        XCTAssertTrue(errorDone, "stderr promise left unfulfilled (would trap at deinit)")
    }
}
