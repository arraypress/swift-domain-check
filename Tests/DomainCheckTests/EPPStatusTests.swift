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
