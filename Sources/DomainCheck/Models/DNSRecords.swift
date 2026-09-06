//
//  DNSRecords.swift
//  DomainCheck
//
//  Created by David Sherlock @ ArrayPress
//
//  What the DNS says about a name. Asked of the system resolver, which is
//  the same one everything else on the machine uses, so the answer here is
//  the answer the machine would act on — cache and search domains included.
//

import Foundation

/// A kind of DNS record.
public enum DNSRecordType: String, CaseIterable, Sendable, Codable {
    /// IPv4 address.
    case a
    /// IPv6 address.
    case aaaa
    /// Mail exchangers.
    case mx
    /// Text records — SPF, DKIM, domain verification.
    case txt
    /// Authoritative name servers.
    case ns
    /// The name this one is an alias for.
    case cname

    /// How it is written in a zone file and in this tool's output.
    public var label: String { rawValue.uppercased() }

    /// The numeric type the resolver wants.
    ///
    /// Values from RFC 1035 and its successors, stated here rather than
    /// imported so the model does not drag in the resolver.
    public var code: UInt16 {
        switch self {
        case .a: return 1
        case .ns: return 2
        case .cname: return 5
        case .mx: return 15
        case .txt: return 16
        case .aaaa: return 28
        }
    }

    /// The types worth asking for when nobody said which.
    public static let common: [DNSRecordType] = [.a, .aaaa, .mx, .txt, .ns]
}

/// What the DNS holds for one name.
public struct DNSRecords: Codable, Sendable, Equatable {
    /// The name asked about.
    public let domain: String
    /// The values found, by type, in the order the resolver gave them.
    public let records: [String: [String]]

    /// - Parameters:
    ///   - domain: The name asked about.
    ///   - records: The values found, keyed by record type label.
    public init(domain: String, records: [String: [String]]) {
        self.domain = domain
        self.records = records
    }

    /// The values of one type.
    ///
    /// - Parameter type: Which record type.
    /// - Returns: Its values, possibly empty.
    public func values(_ type: DNSRecordType) -> [String] {
        records[type.label] ?? []
    }

    /// Whether the name resolves to an address at all.
    ///
    /// A name with MX and TXT but no address is a domain that receives mail
    /// and hosts nothing, which is a real and common arrangement rather
    /// than an error.
    public var resolves: Bool {
        !values(.a).isEmpty || !values(.aaaa).isEmpty
    }

    /// Whether anything at all came back.
    public var isEmpty: Bool { records.values.allSatisfy(\.isEmpty) }

    /// Whether the name accepts mail.
    public var hasMail: Bool { !values(.mx).isEmpty }
}
