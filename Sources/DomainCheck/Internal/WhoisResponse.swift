//
//  WhoisResponse.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//
//  Interpreting free-text WHOIS.
//

import Foundation

/// Reads a WHOIS response into a ``DomainStatus``.
///
/// WHOIS has no schema. Every registry words "no such domain" differently, which
/// is precisely why RDAP is preferred wherever it exists — a `404` needs no
/// interpretation.
///
/// The rule here is deliberately conservative: say ``Availability/available``
/// only on an explicit not-found phrase, say ``Availability/registered`` only on
/// explicit registration data, and otherwise say ``Availability/unknown``.
/// Guessing in either direction is worse than admitting ignorance, and guessing
/// toward "available" is the more expensive mistake.
enum WhoisResponse {

    /// Phrases registries use to say a domain does not exist.
    static let notFoundPhrases = [
        "no match for",
        "no match",
        "not found",
        "no data found",
        "no entries found",
        "no object found",
        "domain not found",
        "object does not exist",
        "nothing found",
        "no matching record",
        "available for registration",
        "is available",
        "free for registration",
        "status: available",
        "status:\t\tavailable",
        "query_status: 220 available",
    ]

    /// Field names that only appear for a registered domain.
    static let registeredMarkers = [
        "domain name:",
        "domain:",
        "creation date:",
        "created:",
        "registered on:",
        "registry expiry date:",
        "expiry date:",
        "registrar:",
        "nserver:",
        "name server:",
    ]

    // MARK: Interpretation

    /// Reads a raw WHOIS body.
    static func status(from response: String, domain: String, server: String, keepingRecord: Bool = false) -> DomainStatus {
        // Comment lines carry legal boilerplate that frequently contains the very
        // phrases being matched — "No match" appears in more than one registry's
        // preamble. Strip them before deciding anything.
        let body = response
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                return !trimmed.hasPrefix("%") && !trimmed.hasPrefix("#") && !trimmed.hasPrefix(">>>")
            }
            .joined(separator: "\n")

        let haystack = body.lowercased()

        if notFoundPhrases.contains(where: haystack.contains) {
            return DomainStatus(domain: domain, availability: .available, source: .whois)
        }

        guard registeredMarkers.contains(where: haystack.contains) else {
            return DomainStatus(
                domain: domain,
                availability: .unknown,
                source: .whois,
                reason: "\(server) returned no recognisable registration data"
            )
        }

        return DomainStatus(
            domain: domain,
            availability: .registered,
            source: .whois,
            registered: date(in: body, keys: ["creation date", "created", "registered on", "registration time"]),
            expires: date(in: body, keys: ["registry expiry date", "expiry date", "expires", "expiration date", "paid-till"]),
            registrar: value(in: body, keys: ["registrar", "sponsoring registrar"]),
            nameservers: values(in: body, keys: ["name server", "nserver"])
                .map { $0.lowercased().split(separator: " ").first.map(String.init) ?? $0.lowercased() }
                .sorted(),
            statuses: EPPStatus.normalise(values(in: body, keys: ["domain status", "status", "state"])),
            updated: date(in: body, keys: ["updated date", "last updated", "changed", "modified"]),
            dnssec: value(in: body, keys: ["dnssec"]).map {
                /// Registries write "signedDelegation", "yes" or "Signed" for
                /// a signed zone and "unsigned" or "no" for an unsigned one.
                let answer = $0.lowercased()
                return !(answer.hasPrefix("unsigned") || answer.hasPrefix("no"))
            },
            registryID: value(in: body, keys: ["registry domain id", "domain id"]),
            record: keepingRecord ? response : nil
        )
    }

    // MARK: Referrals

    /// The registrar's own WHOIS server, when the registry defers to one.
    ///
    /// Many registries are "thin": they confirm a domain exists and list its
    /// nameservers, but hold no dates or registrar name — those live with the
    /// registrar. Without following the referral, a `.io` lookup reports
    /// "registered" and nothing else, which is true but not useful.
    static func referralServer(in response: String) -> String? {
        for line in response.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }

            let name = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            guard name == "registrar whois server" || name == "referralserver" || name == "whois server"
            else { continue }

            var value = parts[1].trimmingCharacters(in: .whitespaces)
            // ReferralServer is published as a URL: whois://whois.example.net
            if let range = value.range(of: "://") { value = String(value[range.upperBound...]) }
            value = value.trimmingCharacters(in: CharacterSet(charactersIn: "/ "))

            if !value.isEmpty { return value }
        }
        return nil
    }

    /// Fills gaps in a registry answer from the registrar's fuller one.
    ///
    /// The registry stays authoritative on *whether* the domain exists; the
    /// registrar only contributes detail.
    static func merging(registry: DomainStatus, registrar detail: DomainStatus) -> DomainStatus {
        DomainStatus(
            domain: registry.domain,
            availability: registry.availability,
            source: .whois,
            registered: registry.registered ?? detail.registered,
            expires: registry.expires ?? detail.expires,
            registrar: registry.registrar ?? detail.registrar,
            nameservers: registry.nameservers.isEmpty ? detail.nameservers : registry.nameservers,
            statuses: registry.statuses.isEmpty ? detail.statuses : registry.statuses,
            updated: registry.updated ?? detail.updated,
            dnssec: registry.dnssec ?? detail.dnssec,
            registryID: registry.registryID ?? detail.registryID,
            /// Both, labelled: the registry record and the registrar's are
            /// different documents, and a caller reading a record wants to
            /// know which server said what.
            record: {
                let both = [registry.record, detail.record].compactMap { $0 }
                return both.isEmpty ? nil : both.joined(separator: "\n\n")
            }(),
            reason: registry.reason
        )
    }

    // MARK: Field Extraction

    /// The first value for any of `keys`, matched case-insensitively.
    static func value(in body: String, keys: [String]) -> String? {
        for line in body.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }

            let name = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            guard keys.contains(name) else { continue }

            let value = parts[1].trimmingCharacters(in: .whitespaces)
            if !value.isEmpty { return value }
        }
        return nil
    }

    /// Every value for any of `keys`.
    static func values(in body: String, keys: [String]) -> [String] {
        var found: [String] = []
        for line in body.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }

            let name = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            guard keys.contains(name) else { continue }

            let value = parts[1].trimmingCharacters(in: .whitespaces)
            if !value.isEmpty { found.append(value) }
        }
        return found
    }

    private static func date(in body: String, keys: [String]) -> Date? {
        guard let raw = value(in: body, keys: keys) else { return nil }
        return RDAPResponse.parseDate(raw)
    }
}
