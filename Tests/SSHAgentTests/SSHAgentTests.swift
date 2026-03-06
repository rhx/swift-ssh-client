import XCTest
@testable import SSHAgent
import NIOSSH

final class SSHAgentTests: XCTestCase {
    func testSSHAgentKey_ed25519() throws {
        let algo = "ssh-ed25519".data(using: .utf8)!
        let pubkey = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20])
        var blob = Data()
        var algoLen = UInt32(algo.count).bigEndian
        blob.append(Data(bytes: &algoLen, count: 4))
        blob.append(algo)
        var pubkeyLen = UInt32(pubkey.count).bigEndian
        blob.append(Data(bytes: &pubkeyLen, count: 4))
        blob.append(pubkey)
        let agentKey = try SSHAgentKey(keyBlob: blob, comment: "test-ed25519")
        let openSSHString = try type(of: agentKey).convertKeyBlobToOpenSSHFormat(blob)
        XCTAssertTrue(openSSHString.starts(with: "ssh-ed25519 "))
        XCTAssertNoThrow(try NIOSSHPublicKey(openSSHPublicKey: openSSHString))
    }

    #if SSHCLIENT_RSA
    func testSSHAgentKey_rsa_valid() throws {
        let blob = try keyBlob(from: Self.rsaPublicKey)
        let agentKey = try SSHAgentKey(keyBlob: blob, comment: "test-rsa")
        let openSSHString = try type(of: agentKey).convertKeyBlobToOpenSSHFormat(blob)
        XCTAssertTrue(openSSHString.starts(with: "ssh-rsa "))
        XCTAssertNoThrow(try NIOSSHPublicKey(openSSHPublicKey: openSSHString))
    }
    #endif

    func testSSHAgentKey_ecdsa_p256() throws {
        let blob = try keyBlob(from: Self.ecdsaP256PublicKey)
        let agentKey = try SSHAgentKey(keyBlob: blob, comment: "test-ecdsa-p256")
        let openSSHString = try type(of: agentKey).convertKeyBlobToOpenSSHFormat(blob)
        XCTAssertTrue(openSSHString.starts(with: "ecdsa-sha2-nistp256 "))
        XCTAssertNoThrow(try NIOSSHPublicKey(openSSHPublicKey: openSSHString))
    }

    func testCreateNIOSSHPrivateKeyPreservesEd25519PublicKey() async throws {
        let algorithm = "ssh-ed25519".data(using: .utf8)!
        let publicKey = Data((1...32).map(UInt8.init))
        let keyBlob = makeKeyBlob(algorithm: algorithm, components: [publicKey])
        let agentKey = try SSHAgentKey(keyBlob: keyBlob, comment: "test-ed25519")

        let nioKey = try await SSHAgent.shared.createNIOSSHPrivateKey(for: agentKey)

        XCTAssertEqual(String(openSSHPublicKey: nioKey.publicKey), String(openSSHPublicKey: agentKey.publicKey))
    }

    #if SSHCLIENT_RSA
    func testSSHAgentSignatureConvertsRSASHA256() throws {
        let agentKey = try makeRSAAgentKey(comment: "rsa-sha2-256")
        let rawSignature = Data((0..<256).map(UInt8.init))
        let wireSignature = makeSSHSignatureWireFormat(algorithm: "rsa-sha2-256", signature: rawSignature)

        let signature = try SSHAgentSignature.convertToNIOSSH(wireSignature, for: agentKey.publicKey)

        XCTAssertEqual(signature, .rsaSHA256(signature: rawSignature))
    }

    func testSSHAgentSignatureConvertsRSASHA512() throws {
        let agentKey = try makeRSAAgentKey(comment: "rsa-sha2-512")
        let rawSignature = Data((0..<255).map { UInt8(($0 + 1) & 0xff) })
        let wireSignature = makeSSHSignatureWireFormat(algorithm: "rsa-sha2-512", signature: rawSignature)

        let signature = try SSHAgentSignature.convertToNIOSSH(wireSignature, for: agentKey.publicKey)

        XCTAssertEqual(signature, .rsaSHA512(signature: rawSignature))
    }

    func testSSHAgentSignatureRejectsUnexpectedRSAAlgorithm() throws {
        let agentKey = try makeRSAAgentKey(comment: "unexpected-rsa")
        let wireSignature = makeSSHSignatureWireFormat(algorithm: "ssh-rsa", signature: Data([0x01, 0x02, 0x03]))

        XCTAssertThrowsError(try SSHAgentSignature.convertToNIOSSH(wireSignature, for: agentKey.publicKey))
    }

    func testCreateNIOSSHPrivateKeyPreservesRSAPublicKey() async throws {
        let agentKey = try makeRSAAgentKey(comment: "test-rsa")

        let nioKey = try await SSHAgent.shared.createNIOSSHPrivateKey(for: agentKey)

        XCTAssertEqual(String(openSSHPublicKey: nioKey.publicKey), String(openSSHPublicKey: agentKey.publicKey))
    }
    #endif

    private func makeKeyBlob(algorithm: Data, components: [Data]) -> Data {
        var blob = Data()
        appendSSHData(algorithm, to: &blob)
        for component in components {
            appendSSHData(component, to: &blob)
        }
        return blob
    }

    private func makeSSHSignatureWireFormat(algorithm: String, signature: Data) -> Data {
        var blob = Data()
        appendSSHData(Data(algorithm.utf8), to: &blob)
        appendSSHData(signature, to: &blob)
        return blob
    }

    #if SSHCLIENT_RSA
    private func makeRSAAgentKey(comment: String) throws -> SSHAgentKey {
        try SSHAgentKey(keyBlob: try keyBlob(from: Self.rsaPublicKey), comment: comment)
    }
    #endif

    private func appendSSHData(_ data: Data, to blob: inout Data) {
        var length = UInt32(data.count).bigEndian
        withUnsafeBytes(of: &length) { blob.append(contentsOf: $0) }
        blob.append(data)
    }

    private func keyBlob(from openSSHPublicKey: String) throws -> Data {
        let components = openSSHPublicKey.split(separator: " ")
        XCTAssertGreaterThanOrEqual(components.count, 2)
        guard let blob = Data(base64Encoded: String(components[1])) else {
            throw SSHAgentError.invalidKeyData("Invalid OpenSSH public key fixture")
        }
        return blob
    }

    private static let rsaPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxBRdD+7MxsGvU9qVSLfQXwfj+NfWYgG3ztUNktFa2Vnt7+726LPrPtKa5Pen2cCJRNQv7m3SMv3wazKj5RxbETlshxz6L5ogWJRrE4XHj0/V2qpw8dWUZ04TgyOr74QG0neCMLenJzNyopjebd8hhhuhITdGqafULl6XvOAdJeKHEYS/md2oYpNcpgYWe/XKtal9vIqPhExjiQdiLwXc7M4W/EmL5JFC9JTOkcjjeAlqsPtKcBqMezCd2e3HJWTr82EJxFcBT0TRf3FXPcsNwncY7w0LrpwW3bQs+51682VxSCGXHb5Mi7d41nDTnh99Yk1bhQwu+GjNqJjsbzkHB test@example.com"

    private static let ecdsaP256PublicKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCXExNZb7xjHBmdcQEp/pTPcuy4XcE++rDgylARa+e54BZHIDGcAL/b0Sg9bZ86nLgKeyPo9rdNf7Ef3N8VyDbo= test@example.com"
}
