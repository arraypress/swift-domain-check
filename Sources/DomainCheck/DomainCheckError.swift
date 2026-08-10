//
//  DomainCheckError.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//

import Foundation

/// Errors thrown while checking a domain.
///
/// Note what is *not* here: "domain is available" and "domain is taken" are both
/// successful outcomes carried by ``DomainStatus``, not errors. Only a failure to
/// determine anything is an error.
public enum DomainCheckError: Error, LocalizedError, Equatable, Sendable {

    /// The input is not a usable domain name.
    case invalidDomain(String)

    /// The IANA RDAP bootstrap could not be fetched or parsed.
    ///
    /// Fatal for the whole run rather than one domain: without it there is no
    /// way to know which server is authoritative for any TLD.
    case bootstrapUnavailable(String)

    /// A registry is rate limiting us.
    case rateLimited(server: String)

    /// A network-level failure.
    case networkError(String)

    /// A response could not be understood.
    case parsingError(String)

    public var errorDescription: String? {
        switch self {
        case .invalidDomain(let domain):
            return "Not a valid domain name: \(domain)"
        case .bootstrapUnavailable(let message):
            return "Could not load the IANA RDAP bootstrap: \(message)"
        case .rateLimited(let server):
            return "Rate limited by \(server)"
        case .networkError(let message):
            return "Network error: \(message)"
        case .parsingError(let message):
            return "Could not parse the response: \(message)"
        }
    }
}
