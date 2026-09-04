//
//  RDAPResponse.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//
//  Turns an RDAP domain object into a DomainStatus.
//

import Foundation

/// Parses RFC 9083 RDAP domain responses.
enum RDAPResponse {

    /// Builds a status from a `200` RDAP body.
    ///
    /// Every field is optional in practice: registries vary in what they publish,
    /// and several redact contact data entirely. A missing field is normal, not
    /// an error — the availability verdict comes from the HTTP status, not from
    /// what the body happens to contain.
    static func status(from data: Data, domain: String, keepingRecord: Bool = false) -> DomainStatus {
        let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]

        var registered: Date?
        var expires: Date?
        var updated: Date?
        for event in root["events"] as? [[String: Any]] ?? [] {
            guard let action = event["eventAction"] as? String,
                  let dateString = event["eventDate"] as? String,
                  let date = parseDate(dateString) else { continue }
            switch action {
            case "registration": registered = date
            case "expiration": expires = date
            /// Not "last update of RDAP database", which is when the registry
            /// last rebuilt its index and says nothing about the domain.
            case "last changed": updated = date
            default: break
            }
        }

        return DomainStatus(
            domain: domain,
            availability: .registered,
            source: .rdap,
            registered: registered,
            expires: expires,
            registrar: registrar(in: root),
            nameservers: nameservers(in: root),
            statuses: EPPStatus.normalise(root["status"] as? [String] ?? []),
            updated: updated,
            dnssec: (root["secureDNS"] as? [String: Any])?["delegationSigned"] as? Bool,
            registryID: root["handle"] as? String,
            record: keepingRecord ? pretty(data) : nil
        )
    }

    /// The body, re-encoded readably.
    ///
    /// Registries send RDAP minified, and a wall of JSON on one line is not a
    /// record anybody can read.
    private static func pretty(_ data: Data) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let formatted = try? JSONSerialization.data(
                withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        else { return String(data: data, encoding: .utf8) }
        return String(data: formatted, encoding: .utf8)
    }

    // MARK: Fields

    /// The sponsoring registrar's name.
    ///
    /// Buried in a jCard: `entities[] where roles contains "registrar"`, then
    /// `vcardArray[1][] where element[0] == "fn"`.
    private static func registrar(in root: [String: Any]) -> String? {
        for entity in root["entities"] as? [[String: Any]] ?? [] {
            let roles = entity["roles"] as? [String] ?? []
            guard roles.contains("registrar") else { continue }

            guard let vcard = entity["vcardArray"] as? [Any], vcard.count > 1,
                  let fields = vcard[1] as? [[Any]] else { continue }

            for field in fields where field.count > 3 {
                if field[0] as? String == "fn", let name = field[3] as? String, !name.isEmpty {
                    return name
                }
            }
        }
        return nil
    }

    private static func nameservers(in root: [String: Any]) -> [String] {
        (root["nameservers"] as? [[String: Any]] ?? [])
            .compactMap { $0["ldhName"] as? String }
            .map { $0.lowercased() }
            .sorted()
    }

    // MARK: Dates

    /// Parses an RDAP timestamp.
    ///
    /// RFC 9083 says RFC 3339, but registries emit fractional seconds, bare
    /// dates, and offsets inconsistently — so several formats are tried rather
    /// than trusting the specification.
    static func parseDate(_ string: String) -> Date? {
        let iso = ISO8601DateFormatter()

        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = iso.date(from: string) { return date }

        iso.formatOptions = [.withInternetDateTime]
        if let date = iso.date(from: string) { return date }

        let fallback = DateFormatter()
        fallback.locale = Locale(identifier: "en_US_POSIX")
        fallback.timeZone = TimeZone(identifier: "UTC")
        for format in ["yyyy-MM-dd'T'HH:mm:ssZ", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd"] {
            fallback.dateFormat = format
            if let date = fallback.date(from: string) { return date }
        }
        return nil
    }
}
