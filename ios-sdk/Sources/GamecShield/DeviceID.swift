import Foundation

public enum DeviceID {
    /// Random id created on first use and kept in UserDefaults. It is cleared when the app is deleted.
    public static func getOrCreate() -> String {
        let key = "gamec.shield.device_id"
        if let id = UserDefaults.standard.string(forKey: key) { return id }
        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "")
        UserDefaults.standard.set(id, forKey: key)
        return id
    }
}
