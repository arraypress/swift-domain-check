//
//  EPPStatus.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//
//  One spelling for a status code, whichever protocol said it.
//

import Foundation

/// Normalises registry status codes.
///
/// RDAP (RFC 9083) publishes them space-separated and lowercase — "client
/// transfer prohibited" — while WHOIS emits the EPP camelCase form,
/// `clientTransferProhibited`, often with a URL after it. A caller matching
/// on one spelling would silently miss every domain answered by the other.
enum EPPStatus {

    /// `"client transfer prohibited"` → `"clientTransferProhibited"`.
    ///
    /// A code this does not recognise is passed through with its whitespace
    /// collapsed rather than dropped: registries invent statuses, and losing
    /// one is worse than reporting it in an unexpected shape.
    static func normalise(_ raw: String) -> String? {
        /// WHOIS appends an explanatory link: "clientTransferProhibited
        /// https://icann.org/epp#clientTransferProhibited".
        let withoutLink = raw.split(whereSeparator: \.isWhitespace)
            .prefix { !$0.hasPrefix("http") }
            .joined(separator: " ")
        let trimmed = withoutLink.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let words = trimmed.split(separator: " ").map(String.init)
        guard words.count > 1 else { return trimmed }

        /// Already camelCase, just spaced oddly, or genuinely several words.
        return words.enumerated().map { index, word in
            index == 0 ? word.lowercased() : word.prefix(1).uppercased() + word.dropFirst().lowercased()
        }.joined()
    }

    static func normalise(_ raw: [String]) -> [String] {
        var seen = Set<String>()
        return raw.compactMap(normalise).filter { seen.insert($0).inserted }
    }
}
