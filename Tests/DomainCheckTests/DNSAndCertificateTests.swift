//
//  DNSAndCertificateTests.swift
//  DomainCheck
//
//  Created by David Sherlock @ ArrayPress
//
//  The wire-format decoding is pure and gets synthetic bytes, because that
//  is where the real hazard is: DNS hands back raw records, not text, and a
//  reader that treats them as strings produces plausible-looking rubbish
//  rather than an error.
//

import XCTest
@testable import DomainCheck

final class DNSDecodingTests: XCTestCase {

    /// Runs the decoder over some bytes as the resolver would supply them.
    func decode(_ bytes: [UInt8], type: DNSRecordType) -> [String] {
        bytes.withUnsafeBytes { DNSResolver.decode($0, rrtype: type.code) }
    }

    func testAnAddressIsFourBytesNotText() {
        XCTAssertEqual(decode([17, 253, 144, 10], type: .a), ["17.253.144.10"])
        XCTAssertEqual(decode([0, 0, 0, 0], type: .a), ["0.0.0.0"])
        XCTAssertEqual(decode([1, 2, 3], type: .a), [], "a short record is not an address")
    }

    func testAnIPv6AddressIsSixteenBytesInGroups() {
        let bytes: [UInt8] = [0x26, 0x20, 0x01, 0x49, 0x0a, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]
        XCTAssertEqual(decode(bytes, type: .aaaa), ["2620:149:af0:0:0:0:0:10"])
        XCTAssertEqual(decode([0x26, 0x20], type: .aaaa), [], "a short record is not an address")
    }

    func testTextRecordsAreLengthPrefixedChunks() {
        // "v=spf1" then "-all" — one record, two chunks. A reader that takes
        // only the first loses half of a long SPF record.
        var bytes: [UInt8] = [6]
        bytes += Array("v=spf1".utf8)
        bytes += [4]
        bytes += Array("-all".utf8)
        XCTAssertEqual(decode(bytes, type: .txt), ["v=spf1", "-all"])
    }

    func testAnEmptyTextChunkEndsTheRecord() {
        XCTAssertEqual(decode([0], type: .txt), [])
    }

    func testNamesAreLengthPrefixedLabels() {
        // 5"apple" 3"com" 0
        var bytes: [UInt8] = [5]
        bytes += Array("apple".utf8)
        bytes += [3]
        bytes += Array("com".utf8)
        bytes += [0]
        XCTAssertEqual(decode(bytes, type: .ns), ["apple.com"])
        XCTAssertEqual(decode(bytes, type: .cname), ["apple.com"])
    }

    func testAMailExchangerSkipsItsPreference() {
        // Two bytes of preference, then the name. Reading from zero yields a
        // name beginning with control characters.
        var bytes: [UInt8] = [0, 10, 2]
        bytes += Array("mx".utf8)
        bytes += [5]
        bytes += Array("apple".utf8)
        bytes += [3]
        bytes += Array("com".utf8)
        bytes += [0]
        XCTAssertEqual(decode(bytes, type: .mx), ["mx.apple.com"])
    }

    func testACompressionPointerStopsRatherThanReadingGarbage() {
        // 0xC0 marks a pointer into the wider message, which is not available
        // here. Following it would read offset bytes as text.
        let bytes: [UInt8] = [3, 0x6E, 0x73, 0x31, 0xC0, 0x0C]
        XCTAssertEqual(decode(bytes, type: .ns), ["ns1"])
    }

    func testRecordTypesCarryTheirWireNumbers() {
        XCTAssertEqual(DNSRecordType.a.code, 1)
        XCTAssertEqual(DNSRecordType.ns.code, 2)
        XCTAssertEqual(DNSRecordType.cname.code, 5)
        XCTAssertEqual(DNSRecordType.mx.code, 15)
        XCTAssertEqual(DNSRecordType.txt.code, 16)
        XCTAssertEqual(DNSRecordType.aaaa.code, 28)
        XCTAssertEqual(DNSRecordType.a.label, "A")
    }
}

final class DNSRecordsTests: XCTestCase {

    func testAskedAndEmptyIsNotTheSameAsNeverAsked() {
        let records = DNSRecords(domain: "example.com", records: ["A": ["1.2.3.4"], "MX": []])
        XCTAssertEqual(records.values(.a), ["1.2.3.4"])
        XCTAssertEqual(records.values(.mx), [], "asked, and there are none")
        XCTAssertEqual(records.values(.txt), [], "never asked reads the same to a caller")
        XCTAssertTrue(records.resolves)
        XCTAssertFalse(records.hasMail)
    }

    func testANameCanReceiveMailWithoutHostingAnything() {
        // A real and common arrangement, not an error.
        let records = DNSRecords(domain: "mail.example", records: ["A": [], "MX": ["mx.example"]])
        XCTAssertFalse(records.resolves)
        XCTAssertTrue(records.hasMail)
        XCTAssertFalse(records.isEmpty)
    }

    func testNothingAtAllIsEmpty() {
        XCTAssertTrue(DNSRecords(domain: "x", records: ["A": [], "MX": []]).isEmpty)
    }
}

final class CertificateTests: XCTestCase {

    func certificate(daysFromNow: Int) -> Certificate {
        Certificate(host: "example.com", port: 443, subject: "example.com",
                    issuer: "Test CA",
                    notAfter: Date().addingTimeInterval(Double(daysFromNow) * 86400),
                    notBefore: Date().addingTimeInterval(-86400 * 30),
                    names: ["example.com", "www.example.com"])
    }

    func testExpiryIsCountedInWholeDays() {
        XCTAssertEqual(certificate(daysFromNow: 60).daysRemaining, 59, accuracy: 1)
        XCTAssertFalse(certificate(daysFromNow: 60).isExpired)
        XCTAssertTrue(certificate(daysFromNow: -1).isExpired)
    }

    func testExpiringSoonUsesTheWindowIssuersWarnIn() {
        XCTAssertFalse(certificate(daysFromNow: 60).expiresSoon())
        XCTAssertTrue(certificate(daysFromNow: 10).expiresSoon())
        XCTAssertTrue(certificate(daysFromNow: -5).expiresSoon(), "already expired counts as soon")
        XCTAssertTrue(certificate(daysFromNow: 60).expiresSoon(within: 90))
    }

    func testACertificateNotYetValidIsItsOwnCase() {
        let future = Certificate(host: "x", port: 443, subject: "x", issuer: "y",
                                 notAfter: Date().addingTimeInterval(86400 * 400),
                                 notBefore: Date().addingTimeInterval(86400 * 10), names: [])
        XCTAssertTrue(future.isNotYetValid)
        XCTAssertFalse(future.isExpired)
    }
}

private func XCTAssertEqual(_ a: Int, _ b: Int, accuracy: Int, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertTrue(abs(a - b) <= accuracy, "\(a) is not within \(accuracy) of \(b)", file: file, line: line)
}
