// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "ssh-client",
    platforms: [
        .macOS(.v13),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    traits: [
        .default(enabledTraits: []),
        .trait(
            name: "RSA",
            description: "Enable RSA ssh-agent signatures and RSA support in swift-nio-ssh."
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.83.0"),
        .package(
            url: "https://github.com/rhx/swift-nio-ssh/",
            branch: "rsa-agent",
            traits: [
                .defaults,
                .trait(name: "RSA", condition: .when(traits: ["RSA"])),
            ]
        ),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/mipalgu/swift-docc-static", branch: "main"),
    ],
    targets: [
        .target(
            name: "SSHAgent",
            dependencies: [
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            swiftSettings: [
                .define("SSHCLIENT_RSA", .when(traits: ["RSA"])),
            ]
        ),
        .target(
            name: "SSHClient",
            dependencies: [
                "SSHAgent",
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            swiftSettings: [
                .define("SSHCLIENT_RSA", .when(traits: ["RSA"])),
            ]
        ),
        .executableTarget(
            name: "ssh-client",
            dependencies: [
                "SSHClient",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: [
                .define("SSHCLIENT_RSA", .when(traits: ["RSA"])),
            ]
        ),
        .testTarget(
            name: "SSHAgentTests",
            dependencies: [
                "SSHAgent",
            ],
            swiftSettings: [
                .define("SSHCLIENT_RSA", .when(traits: ["RSA"])),
            ]
        ),
        .testTarget(
            name: "SSHClientTests",
            dependencies: [
                "SSHClient",
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ],
            swiftSettings: [
                .define("SSHCLIENT_RSA", .when(traits: ["RSA"])),
            ]
        ),
        .testTarget(
            name: "ssh-clientTests",
            dependencies: [
                "ssh-client",
            ],
            swiftSettings: [
                .define("SSHCLIENT_RSA", .when(traits: ["RSA"])),
            ]
        ),
    ]
)
