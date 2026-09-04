//
//  EPPStatusTests.swift
//  DomainCheckTests
//
//  One spelling for a status code, whichever protocol said it.
//

import Foundation
import XCTest
@testable import DomainCheck

final class EPPStatusTests: XCTestCase {

    func testRDAPsSpacedLowercaseBecomesEPPCamelCase() {
        // RFC 9083 publishes "client transfer prohibited"; WHOIS publishes
        // "clientTransferProhibited". A caller matching one spelling would
        // silently miss every domain answered by the other protocol.
        XCTAssertEqual(EPPStatus.normalise("client transfer prohibited"), "clientTransferProhibited")
        XCTAssertEqual(EPPStatus.normalise("client delete prohibited"), "clientDeleteProhibited")
        XCTAssertEqual(EPPStatus.normalise("pending delete"), "pendingDelete")
    }

    func testAlreadyCamelCaseIsLeftAlone() {
        XCTAssertEqual(EPPStatus.normalise("clientTransferProhibited"), "clientTransferProhibited")
        XCTAssertEqual(EPPStatus.normalise("ok"), "ok")
    }

    func testWHOISsTrailingLinkIsDropped() {
        // Registries append the explanatory URL to the same line.
        XCTAssertEqual(
            EPPStatus.normalise("clientTransferProhibited https://icann.org/epp#clientTransferProhibited"),
            "clientTransferProhibited")
    }

    func testAnUnknownCodeIsKeptNotDropped() {
        // Registries invent statuses; losing one is worse than reporting it
        // in a shape the caller did not expect.
        XCTAssertEqual(EPPStatus.normalise("serverRenewProhibited"), "serverRenewProhibited")
        XCTAssertEqual(EPPStatus.normalise("some future state"), "someFutureState")
    }

    func testBlanksAreDropped() {
        XCTAssertNil(EPPStatus.normalise("   "))
        XCTAssertNil(EPPStatus.normalise(""))
    }

    func testDuplicatesCollapseAcrossSpellings() {
        // A record carrying both forms must not report the same lock twice.
        XCTAssertEqual(
            EPPStatus.normalise(["client transfer prohibited", "clientTransferProhibited", "ok"]),
            ["clientTransferProhibited", "ok"])
    }
}

final class LockAndLapseTests: XCTestCase {

    private func status(_ codes: [String]) -> DomainStatus {
        DomainStatus(domain: "x.com", availability: .registered, source: .rdap, statuses: codes)
    }

    func testALockedNameIsReportedAsSuch() {
        // The status a caller planning a transfer actually needs.
        XCTAssertTrue(status(["clientTransferProhibited"]).isLocked)
        XCTAssertTrue(status(["serverTransferProhibited"]).isLocked)
        XCTAssertFalse(status(["ok"]).isLocked)
        XCTAssertFalse(status([]).isLocked)
    }

    func testALapsingNameIsReportedAsSuch() {
        // The only states in which a taken name is about to become free.
        XCTAssertTrue(status(["redemptionPeriod"]).isLapsing)
        XCTAssertTrue(status(["pendingDelete"]).isLapsing)
        XCTAssertFalse(status(["clientTransferProhibited"]).isLapsing)
    }
}

final class CRLFRecordTests: XCTestCase {

    /// A real registry answer, CRLF-terminated as RFC 3912 requires.
    private let record = [
        "Domain Name: example.io",
        "Registry Domain ID: REDACTED",
        "Registrar WHOIS Server: whois.namecheap.com",
        "Updated Date: 2026-08-11T23:28:18Z",
        "Creation Date: 2011-11-22T01:38:41Z",
        "Registry Expiry Date: 2026-11-22T01:38:41Z",
        "Registrar: NameCheap, Inc.",
        "Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
        "Name Server: ns1.digitalocean.com",
        "Name Server: ns2.digitalocean.com",
        "DNSSEC: unsigned",
        "",
    ].joined(separator: "\r\n")

    func testACRLFRecordParses() {
        // The bug this pins down, and it was completely silent: Swift treats
        // "\r\n" as ONE Character, so `split(separator: "\n")` matched
        // nothing and handed the whole document back as a single line. Every
        // field came out nil while the verdict still read "registered", so
        // every WHOIS-only TLD — .io, .sh and the rest — answered with a bare
        // "registered" and no detail at all.
        let status = WhoisResponse.status(from: record, domain: "example.io", server: "whois.nic.io")

        XCTAssertEqual(status.availability, .registered)
        XCTAssertEqual(status.registrar, "NameCheap, Inc.")
        XCTAssertEqual(status.statuses, ["clientTransferProhibited"])
        XCTAssertEqual(status.nameservers, ["ns1.digitalocean.com", "ns2.digitalocean.com"])
        XCTAssertEqual(status.dnssec, false)
        XCTAssertNotNil(status.registered)
        XCTAssertNotNil(status.expires)
        XCTAssertNotNil(status.updated)
        XCTAssertTrue(status.isLocked)
    }

    func testTheSameRecordWithBareNewlinesParsesIdentically() {
        let lf = record.replacingOccurrences(of: "\r\n", with: "\n")
        let fromCRLF = WhoisResponse.status(from: record, domain: "example.io", server: "s")
        let fromLF = WhoisResponse.status(from: lf, domain: "example.io", server: "s")
        XCTAssertEqual(fromCRLF, fromLF)
    }

    func testTheReferralServerIsFoundInACRLFRecord() {
        // Without this the registrar is never consulted, and a .io lookup
        // reports "registered" and nothing else.
        XCTAssertEqual(WhoisResponse.referralServer(in: record), "whois.namecheap.com")
    }
}

final class RedactionTests: XCTestCase {

    func testAPlaceholderIsNotData() {
        // Since GDPR most registries answer identifier fields with a literal
        // "REDACTED FOR PRIVACY". Reporting that as the registry ID is worse
        // than reporting nothing — it looks like data, so a caller stores it,
        // compares it, and eventually acts on it.
        XCTAssertTrue(WhoisResponse.isRedacted("REDACTED"))
        XCTAssertTrue(WhoisResponse.isRedacted("REDACTED FOR PRIVACY"))
        XCTAssertTrue(WhoisResponse.isRedacted("Not Disclosed"))
        XCTAssertTrue(WhoisResponse.isRedacted("n/a"))
        XCTAssertFalse(WhoisResponse.isRedacted("NameCheap, Inc."))
        XCTAssertFalse(WhoisResponse.isRedacted("1264983250_DOMAIN_COM-VRSN"))
    }

    func testARedactedFieldComesBackNilNotAsThePlaceholder() {
        let record = [
            "Domain Name: example.io",
            "Registry Domain ID: REDACTED FOR PRIVACY",
            "Registrar: NameCheap, Inc.",
            "Creation Date: 2011-11-22T01:38:41Z",
            "",
        ].joined(separator: "\r\n")
        let status = WhoisResponse.status(from: record, domain: "example.io", server: "s")
        XCTAssertNil(status.registryID)
        XCTAssertEqual(status.registrar, "NameCheap, Inc.")
    }
}
