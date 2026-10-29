// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "GamecShield",
    // SecTrustCopyCertificateChain needs iOS 15; TLS 1.3 itself works from iOS 12.2.
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [.library(name: "GamecShield", targets: ["GamecShield"])],
    targets: [.target(name: "GamecShield")]
)
