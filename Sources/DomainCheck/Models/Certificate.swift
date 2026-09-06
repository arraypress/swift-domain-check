//
//  Certificate.swift
//  DomainCheck
//
//  Created by David Sherlock @ ArrayPress
//
//  The certificate a host actually presents, read from the TLS handshake
//  rather than from a database. Reported even when it is expired or
//  untrusted — a certificate that expired last week is exactly the thing
//  somebody needs told, and a tool that refuses to describe it is useless
//  at the one moment it matters.
//

import Foundation

/// The certificate a host presented.
public struct Certificate: Codable, Sendable, Equatable {
    /// The host asked.
    public let host: String
    /// The port asked.
    public let port: Int
    /// What the certificate says it is for.
    public let subject: String
    /// Who signed it.
    public let issuer: String
    /// When it stops being valid.
    public let notAfter: Date
    /// When it started being valid.
    public let notBefore: Date
    /// The names it covers, from the subject alternative names.
    public let names: [String]

    /// - Parameters:
    ///   - host: The host asked.
    ///   - port: The port asked.
    ///   - subject: What the certificate is for.
    ///   - issuer: Who signed it.
    ///   - notAfter: When it expires.
    ///   - notBefore: When it became valid.
    ///   - names: The names it covers.
    public init(host: String, port: Int, subject: String, issuer: String,
                notAfter: Date, notBefore: Date, names: [String]) {
        self.host = host
        self.port = port
        self.subject = subject
        self.issuer = issuer
        self.notAfter = notAfter
        self.notBefore = notBefore
        self.names = names
    }

    /// Whole days until it expires. Negative once it has.
    public var daysRemaining: Int {
        Int(notAfter.timeIntervalSinceNow / 86400)
    }

    /// Whether it has already expired.
    public var isExpired: Bool { notAfter < Date() }

    /// Whether it is not yet valid — a clock problem, or a certificate
    /// installed early.
    public var isNotYetValid: Bool { notBefore > Date() }

    /// Whether it expires soon enough to act on.
    ///
    /// - Parameter days: How much warning counts as soon. Thirty by
    ///   default, which is the window most issuers start reminding in.
    /// - Returns: True when it expires within that many days, or already has.
    public func expiresSoon(within days: Int = 30) -> Bool {
        daysRemaining <= days
    }
}
