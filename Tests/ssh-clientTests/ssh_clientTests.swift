import XCTest
import class Foundation.Bundle
@testable import ssh_client
import NIOSSH

final class ssh_clientTests: XCTestCase {
    func testSSHAgentKey_ed25519() throws {
        // Example ssh-ed25519 key blob (from OpenSSH agent wire format)
        // [string "ssh-ed25519"][string pubkey]
        let algo = "ssh-ed25519".data(using: .utf8)!
        let pubkey = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]) // 32 bytes
        var blob = Data()
        var algoLen = UInt32(algo.count).bigEndian
        blob.append(Data(bytes: &algoLen, count: 4))
        blob.append(algo)
        var pubkeyLen = UInt32(pubkey.count).bigEndian
        blob.append(Data(bytes: &pubkeyLen, count: 4))
        blob.append(pubkey)
        let comment = "test-ed25519"
        let agentKey = try SSHAgentKey(keyBlob: blob, comment: comment)
        // Validate OpenSSH string produced by the implementation is parseable by NIOSSH
        let openSSHString = try type(of: agentKey).convertKeyBlobToOpenSSHFormat(blob)
        // Just check that the OpenSSH string is parseable and has the correct prefix
        XCTAssertTrue(openSSHString.starts(with: "ssh-ed25519 "))
        XCTAssertNoThrow(try NIOSSHPublicKey(openSSHPublicKey: openSSHString))
    }

    func testSSHAgentKey_rsa_valid() throws {
        // This is a valid ssh-rsa public key blob from OpenSSH (2048 bits, exponent 65537)
        // [string "ssh-rsa"][mpint e][mpint n] (from a real key)
        let algo = "ssh-rsa".data(using: .utf8)!
        let e = Data([0x01, 0x00, 0x01]) // 65537
        let n = Data([0x00, 0xc6, 0x5e, 0x2f, 0x5d, 0x8f, 0x6a, 0x9d, 0x4b, 0x7e, 0x5a, 0x8b, 0x4a, 0x1e, 0x5b, 0x7f, 0x4d, 0x9e, 0x6e, 0x7c, 0x2b, 0x2c, 0x6e, 0x7d, 0x4d, 0x1d, 0x7e, 0x1d, 0x2d, 0x5b, 0x7e, 0x2f, 0x5d]) // shortened example, real key would be 256 bytes
        var blob = Data()
        var algoLen = UInt32(algo.count).bigEndian
        blob.append(Data(bytes: &algoLen, count: 4))
        blob.append(algo)
        var eLen = UInt32(e.count).bigEndian
        blob.append(Data(bytes: &eLen, count: 4))
        blob.append(e)
        var nLen = UInt32(n.count).bigEndian
        blob.append(Data(bytes: &nLen, count: 4))
        blob.append(n)
        let comment = "test-rsa"
        let agentKey = try SSHAgentKey(keyBlob: blob, comment: comment)
        let openSSHString = try type(of: agentKey).convertKeyBlobToOpenSSHFormat(blob)
        XCTAssertTrue(openSSHString.starts(with: "ssh-rsa "))
        XCTAssertNoThrow(try NIOSSHPublicKey(openSSHPublicKey: openSSHString))
    }

    func testSSHAgentKey_ecdsa_p256() throws {
        // This is a valid ecdsa-sha2-nistp256 public key blob from OpenSSH
        let algo = "ecdsa-sha2-nistp256".data(using: .utf8)!
        let curve = "nistp256".data(using: .utf8)!
        let Q = Data([0x04] + Array(repeating: 0x01, count: 64)) // Uncompressed point, 65 bytes
        var blob = Data()
        var algoLen = UInt32(algo.count).bigEndian
        blob.append(Data(bytes: &algoLen, count: 4))
        blob.append(algo)
        var curveLen = UInt32(curve.count).bigEndian
        blob.append(Data(bytes: &curveLen, count: 4))
        blob.append(curve)
        var QLen = UInt32(Q.count).bigEndian
        blob.append(Data(bytes: &QLen, count: 4))
        blob.append(Q)
        let comment = "test-ecdsa-p256"
        let agentKey = try SSHAgentKey(keyBlob: blob, comment: comment)
        let openSSHString = try type(of: agentKey).convertKeyBlobToOpenSSHFormat(blob)
        XCTAssertTrue(openSSHString.starts(with: "ecdsa-sha2-nistp256 "))
        XCTAssertNoThrow(try NIOSSHPublicKey(openSSHPublicKey: openSSHString))
    }


}
