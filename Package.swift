// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "ssh-client",
    platforms: [
        .macOS(.v13),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.83.0"),
        .package(url: "https://github.com/apple/swift-nio-ssh.git", from: "0.10.0"),
    ],
    targets: [
        .executableTarget(
            name: "ssh-client",
            dependencies: [
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),            ]
        ),
        .testTarget(
            name: "ssh-clientTests",
            dependencies: ["ssh-client"]),
    ]
)
