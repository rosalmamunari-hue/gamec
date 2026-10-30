// swift-tools-version:5.7
// Lives at the repository root so the SDK can be added in Xcode by repository URL and version tag.
// The sources are in ios-sdk/.
import PackageDescription

let package = Package(
    name: "GamecShield",
    // SecTrustCopyCertificateChain needs iOS 15; TLS 1.3 itself works from iOS 12.2.
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [.library(name: "GamecShield", targets: ["GamecShield"])],
    targets: [
        .target(name: "GamecShield", path: "ios-sdk/Sources/GamecShield"),
        .testTarget(name: "GamecShieldTests", dependencies: ["GamecShield"], path: "ios-sdk/Tests/GamecShieldTests"),
    ]
)
