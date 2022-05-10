// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ssh-client",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio-ssh.git", branch: "main"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .executableTarget(
            name: "ssh-client",
            dependencies: [.product(name: "NIOSSH", package: "swift-nio-ssh")]),
        .testTarget(
            name: "ssh-clientTests",
            dependencies: ["ssh-client"]),
    ]
)
