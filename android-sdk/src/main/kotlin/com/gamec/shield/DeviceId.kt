package com.gamec.shield

import android.content.Context
import java.util.UUID

object DeviceId {
    /** Random id created on first use and kept in app-private storage. It is cleared on uninstall. */
    fun getOrCreate(context: Context): String {
        val prefs = context.getSharedPreferences("gamec_shield", Context.MODE_PRIVATE)
        prefs.getString("device_id", null)?.let { return it }
        val id = UUID.randomUUID().toString().replace("-", "")
        prefs.edit().putString("device_id", id).apply()
        return id
    }
}
