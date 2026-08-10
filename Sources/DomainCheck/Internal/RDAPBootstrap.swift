//
//  RDAPBootstrap.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//
//  IANA's TLD → RDAP server registry.
//

import Foundation

/// Maps a TLD to the RDAP service authoritative for it.
///
/// Parsed from IANA's published bootstrap file, never hardcoded. This is the
/// single most important correctness property in the library: a `404` from a
/// server that is *not* authoritative for a TLD means nothing at all, and
/// reading one as "available" is how you tell someone a registered domain is
/// free.
struct RDAPBootstrap: Sendable {

    /// TLD → service base URL, e.g. `"tools"` → `https://rdap.identitydigital.services/rdap`.
    private let servers: [String: String]

    /// The number of TLDs covered.
    var coverage: Int { servers.count }

    // MARK: Initialisation

    /// Parses IANA's `dns.json`.
    ///
    /// The file's shape is `services: [ [[tlds], [urls]] ]`.
    init(json: Data) throws(DomainCheckError) {
        guard let root = (try? JSONSerialization.jsonObject(with: json)) as? [String: Any],
              let services = root["services"] as? [[Any]] else {
            throw .bootstrapUnavailable("unexpected bootstrap shape")
        }

        var servers: [String: String] = [:]
        for service in services {
            guard service.count >= 2,
                  let tlds = service[0] as? [String],
                  let urls = service[1] as? [String] else { continue }

            // Prefer HTTPS where a service lists both.
            let url = urls.first { $0.hasPrefix("https://") } ?? urls.first
            guard let url else { continue }

            let base = url.hasSuffix("/") ? String(url.dropLast()) : url
            for tld in tlds {
                servers[tld.lowercased()] = base
            }
        }

        guard !servers.isEmpty else {
            throw .bootstrapUnavailable("bootstrap contained no services")
        }
        self.servers = servers
    }

    // MARK: Lookup

    /// The RDAP query URL for a domain, or `nil` when its TLD has no RDAP service.
    ///
    /// A `nil` here is not a failure — roughly a hundred TLDs including `.io`
    /// and `.sh` publish no RDAP service, and those fall through to WHOIS.
    func queryURL(for domain: String) -> URL? {
        guard let tld = domain.split(separator: ".").last.map(String.init)?.lowercased(),
              let base = servers[tld] else { return nil }
        return URL(string: "\(base)/domain/\(domain)")
    }

    /// Whether a TLD is served by RDAP.
    func hasService(forTLD tld: String) -> Bool {
        servers[tld.lowercased()] != nil
    }
}
