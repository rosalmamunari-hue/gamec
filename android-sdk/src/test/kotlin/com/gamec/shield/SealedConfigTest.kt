package com.gamec.shield

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class SealedConfigTest {
    /** Produced by the real edge code (shieldlist.SealConfig), so the implementations agree. */
    private val blob = "M9quLvIRWDENSWa-oXXQs-cydRpjWmKd2eFBiwqxBh7s5SoTHDzZg0u-qM3KMiuKm6soilUc_-niZ1oiIS1X8EUYTVD8G8RHSK3eRqemhsxOscvws8h2IgDTFnamVkGBmMDrRh9qATFIYXC2xeyl"

    @Test
    fun aConfigSealedByTheGoCodeOpens() {
        val c = SealedConfig.open(blob, "test-passphrase")
        assertEquals("wap.example.com", c.name)
        assertEquals(listOf("update.example.org"), c.fallbackNames)
        assertEquals("PUBKEY123", c.publicKey)
        assertEquals("LISTKEY456", c.listKey)
    }

    @Test
    fun theWrongPassphraseOrADamagedConfigIsRefused() {
        try {
            SealedConfig.open(blob, "nope")
            fail("opened with the wrong passphrase")
        } catch (_: Exception) {
        }
        try {
            SealedConfig.open(blob.dropLast(3) + "AAA", "test-passphrase")
            fail("opened a damaged config")
        } catch (_: Exception) {
        }
    }

    @Test
    fun theBlobHidesTheNames() {
        assertEquals(-1, blob.indexOf("example"))
    }
}
