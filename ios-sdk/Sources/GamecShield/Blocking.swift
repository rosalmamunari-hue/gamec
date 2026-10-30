import Foundation

/// Runs blocking work (semaphores, sleeps, network waits) on a thread of its own instead of GCD's shared pool.
/// The pool has a small fixed number of threads; filling it with waits during a mass reconnect would also
/// starve the TLS pin checks and connection callbacks that the waits are waiting for.
enum Blocking {
    static func run(_ name: String, _ work: @escaping () -> Void) {
        let t = Thread(block: work)
        t.name = name
        t.start()
    }
}
