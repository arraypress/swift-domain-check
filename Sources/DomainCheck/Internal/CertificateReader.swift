//
//  CertificateReader.swift
//  DomainCheck
//
//  Created by David Sherlock @ ArrayPress
//
//  The certificate a host actually presents, read out of the TLS handshake.
//
//  It is read in the VERIFY BLOCK, before the system decides whether to
//  trust it. That is deliberate and it is the whole point: a certificate
//  that expired last week is exactly the one somebody needs described, and
//  a reader that waits for a successful handshake can never describe it.
//
//  Verified against expired.badssl.com, whose certificate expired in 2015
//  and which this reads without complaint.
//

import Foundation
import Network
import Security

/// Reads the certificate a host presents.
enum CertificateReader {

    /// The leaf certificate from a host's TLS handshake.
    ///
    /// - Parameters:
    ///   - host: The host to connect to.
    ///   - port: The port. 443 unless told otherwise.
    ///   - timeout: How long to wait before giving up.
    /// - Returns: The certificate, or nil when the host did not present one.
    static func read(host: String, port: UInt16 = 443,
                     timeout: TimeInterval = 8) async -> Certificate? {
        await withCheckedContinuation { continuation in
            let state = ResumeGuard()
            let options = NWProtocolTLS.Options()

            sec_protocol_options_set_verify_block(
                options.securityProtocolOptions,
                { _, trustRef, complete in
                    let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
                    let certificate = Self.describe(trust: trust, host: host, port: Int(port))
                    state.finish(certificate) { continuation.resume(returning: $0) }
                    // Always true: this is an inspection, not an authentication.
                    // Refusing here would close the connection before an expired
                    // or self-signed certificate could be reported, which is the
                    // case that matters most.
                    complete(true)
                },
                DispatchQueue.global())

            guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
                return continuation.resume(returning: nil)
            }
            let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort,
                                          using: NWParameters(tls: options))
            connection.stateUpdateHandler = { update in
                switch update {
                case .ready, .cancelled:
                    connection.cancel()
                case .failed, .waiting:
                    state.finish(nil) { continuation.resume(returning: $0) }
                    connection.cancel()
                default:
                    break
                }
            }
            connection.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                state.finish(nil) { continuation.resume(returning: $0) }
                connection.cancel()
            }
        }
    }

    /// Resumes a continuation exactly once.
    ///
    /// The verify block, the state handler and the timeout can all fire, and
    /// resuming a continuation twice is a crash rather than a warning.
    private final class ResumeGuard: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false

        func finish(_ value: Certificate?, _ resume: (Certificate?) -> Void) {
            lock.lock()
            let first = !done
            done = true
            lock.unlock()
            if first { resume(value) }
        }
    }

    /// Turns a trust object into a description of its leaf certificate.
    static func describe(trust: SecTrust, host: String, port: Int) -> Certificate? {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first else { return nil }

        let subject = SecCertificateCopySubjectSummary(leaf) as String? ?? host
        var error: Unmanaged<CFError>?
        let wanted = [kSecOIDX509V1ValidityNotAfter, kSecOIDX509V1ValidityNotBefore,
                      kSecOIDX509V1IssuerName, kSecOIDSubjectAltName] as CFArray
        let values = SecCertificateCopyValues(leaf, wanted, &error) as? [CFString: Any]

        func date(_ key: CFString) -> Date? {
            guard let entry = values?[key] as? [CFString: Any],
                  let seconds = entry[kSecPropertyKeyValue] as? Double else { return nil }
            // Certificate times come back as seconds since 2001-01-01, not 1970.
            return Date(timeIntervalSinceReferenceDate: seconds)
        }

        var issuer = "unknown"
        if let entry = values?[kSecOIDX509V1IssuerName] as? [CFString: Any],
           let parts = entry[kSecPropertyKeyValue] as? [[CFString: Any]] {
            // MEASURED: the label is the OID, "2.5.4.3", NOT "CN". Matching on
            // "CN" finds nothing and every issuer reads as unknown.
            for part in parts where (part[kSecPropertyKeyLabel] as? String) == "2.5.4.3" {
                issuer = part[kSecPropertyKeyValue] as? String ?? issuer
            }
        }

        var names: [String] = []
        if let entry = values?[kSecOIDSubjectAltName] as? [CFString: Any],
           let parts = entry[kSecPropertyKeyValue] as? [[CFString: Any]] {
            // MEASURED: the alternative-name list also carries a "Critical"
            // entry whose value is the string "No". Taking every value puts
            // "No" at the head of the names a certificate covers.
            for part in parts where (part[kSecPropertyKeyLabel] as? String) == "DNS Name" {
                if let value = part[kSecPropertyKeyValue] as? String { names.append(value) }
            }
        }

        return Certificate(host: host, port: port, subject: subject, issuer: issuer,
                           notAfter: date(kSecOIDX509V1ValidityNotAfter) ?? .distantPast,
                           notBefore: date(kSecOIDX509V1ValidityNotBefore) ?? .distantPast,
                           names: names)
    }
}
