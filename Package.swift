// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "Argus",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "Argus",
            path: "Sources/Argus"
        )
    ]
)
