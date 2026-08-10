// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DomainCheck",
    // Pure Foundation and POSIX sockets — no Apple frameworks — so this stays
    // usable on Linux even though the CLI built on it targets macOS.
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
        .tvOS(.v17),
        .watchOS(.v10)
    ],
    products: [
        .library(
            name: "DomainCheck",
            targets: ["DomainCheck"]
        ),
    ],
    targets: [
        .target(
            name: "DomainCheck",
            dependencies: []
        ),
        .testTarget(
            name: "DomainCheckTests",
            dependencies: ["DomainCheck"]
        ),
    ]
)
