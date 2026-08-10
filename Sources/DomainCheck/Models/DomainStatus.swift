//
//  DomainStatus.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//

import Foundation

// MARK: - Availability

/// Whether a domain can be registered.
public enum Availability: String, Codable, Sendable, CaseIterable {

    /// The registry has no record of it.
    case available

    /// Someone holds it.
    case registered

    /// Neither RDAP nor WHOIS could give a trustworthy answer.
    ///
    /// A distinct case on purpose. Collapsing "we could not tell" into
    /// "available" is how a checker convinces someone to build a brand on a name
    /// they cannot have — the single worst thing this library could do.
    case unknown
}

// MARK: - Source

/// Which protocol produced an answer.
public enum StatusSource: String, Codable, Sendable, CaseIterable {

    /// The registry's RDAP service. Authoritative and structured.
    case rdap

    /// Port-43 WHOIS. Authoritative but unstructured.
    case whois

    /// No source could answer.
    case none
}

// MARK: - Status

/// The result of checking one domain.
public struct DomainStatus: Codable, Sendable, Equatable, Identifiable {

    /// The domain checked, normalised to lowercase.
    public let domain: String

    public var id: String { domain }

    /// Whether it can be registered.
    public let availability: Availability

    /// Which protocol answered.
    public let source: StatusSource

    /// When it was registered, when the source says.
    public let registered: Date?

    /// When the registration expires.
    ///
    /// Worth surfacing: a domain expiring in three weeks is a very different
    /// prospect from one paid up until 2031.
    public let expires: Date?

    /// The sponsoring registrar, when reported.
    public let registrar: String?

    /// Delegated nameservers, when reported.
    public let nameservers: [String]

    /// Why the answer is ``Availability/unknown``, when it is.
    public let reason: String?

    public init(
        domain: String,
        availability: Availability,
        source: StatusSource,
        registered: Date? = nil,
        expires: Date? = nil,
        registrar: String? = nil,
        nameservers: [String] = [],
        reason: String? = nil
    ) {
        self.domain = domain
        self.availability = availability
        self.source = source
        self.registered = registered
        self.expires = expires
        self.registrar = registrar
        self.nameservers = nameservers
        self.reason = reason
    }

    /// Days until expiry, when known.
    ///
    /// - Parameter now: The reference date. Injected rather than read from the
    ///   clock so results stay reproducible in tests.
    public func daysUntilExpiry(from now: Date = Date()) -> Int? {
        guard let expires else { return nil }
        return Calendar(identifier: .gregorian)
            .dateComponents([.day], from: now, to: expires).day
    }
}
