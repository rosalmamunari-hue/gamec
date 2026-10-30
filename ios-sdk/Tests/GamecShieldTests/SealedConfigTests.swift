import XCTest
@testable import GamecShield

final class SealedConfigTests: XCTestCase {
    /// Produced by the real edge code (shieldlist.SealConfig), so the implementations agree.
    private let blob = "M9quLvIRWDENSWa-oXXQs-cydRpjWmKd2eFBiwqxBh7s5SoTHDzZg0u-qM3KMiuKm6soilUc_-niZ1oiIS1X8EUYTVD8G8RHSK3eRqemhsxOscvws8h2IgDTFnamVkGBmMDrRh9qATFIYXC2xeyl"

    func testAConfigSealedByTheGoCodeOpens() throws {
        let c = try SealedConfig.open(blob, passphrase: "test-passphrase")
        XCTAssertEqual(c.name, "wap.example.com")
        XCTAssertEqual(c.fallbackNames, ["update.example.org"])
        XCTAssertEqual(c.publicKey, "PUBKEY123")
        XCTAssertEqual(c.listKey, "LISTKEY456")
    }

    func testTheWrongPassphraseOrADamagedConfigIsRefused() {
        XCTAssertThrowsError(try SealedConfig.open(blob, passphrase: "nope"))
        XCTAssertThrowsError(try SealedConfig.open(String(blob.dropLast(3)) + "AAA", passphrase: "test-passphrase"))
    }
}
