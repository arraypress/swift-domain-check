//
//  RegistryThrottle.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//

import Foundation

/// Spaces requests out per server.
///
/// Keyed by server rather than globally, because registries rate limit
/// independently: checking a hundred names across twenty TLDs should run twenty
/// ways in parallel and only queue behind itself per registry. A global limiter
/// would be needlessly slow; no limiter at all earns a `429`, which is how six
/// concurrent lookups against Google's registry got throttled in testing.
actor RegistryThrottle {

    private let interval: TimeInterval
    private var nextAllowed: [String: Date] = [:]

    init(interval: TimeInterval) {
        self.interval = interval
    }

    /// Waits until this server may be called again, then reserves the next slot.
    func reserve(_ server: String) async {
        guard interval > 0 else { return }

        let now = Date()
        let earliest = nextAllowed[server] ?? now
        let delay = earliest.timeIntervalSince(now)

        // Reserved before sleeping so concurrent callers queue behind each other
        // rather than all waking into the same slot.
        nextAllowed[server] = max(earliest, now).addingTimeInterval(interval)

        if delay > 0 {
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
    }

    /// Pushes a server's next slot out, after it has told us to back off.
    func penalise(_ server: String, seconds: TimeInterval) {
        let until = Date().addingTimeInterval(seconds)
        nextAllowed[server] = max(nextAllowed[server] ?? until, until)
    }
}
