//
//  DomainCheckTests.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//
//  Offline throughout: the bootstrap is injected and every parser is fed a
//  fixture, so the suite is deterministic and needs no registry.
//

import XCTest
@testable import DomainCheck

final class DomainCheckTests: XCTestCase {

    // MARK: - Bootstrap

    private let bootstrapJSON = Data("""
    {
      "version": "1.0",
      "services": [
        [["com","net"], ["https://rdap.verisign.com/com/v1/"]],
        [["dev","app"], ["http://insecure.example/", "https://pubapi.registry.google/rdap/"]],
        [["tools"],     ["https://rdap.identitydigital.services/rdap"]]
      ]
    }
    """.utf8)

    private func bootstrap() throws -> RDAPBootstrap {
        try RDAPBootstrap(json: bootstrapJSON)
    }

    func testBootstrapMapsEveryTLDInAService() throws {
        let b = try bootstrap()
        XCTAssertEqual(b.coverage, 5)
        XCTAssertTrue(b.hasService(forTLD: "com"))
        XCTAssertTrue(b.hasService(forTLD: "app"))
    }

    func testBootstrapPrefersHTTPS() throws {
        let url = try XCTUnwrap(bootstrap().queryURL(for: "example.dev"))
        XCTAssertEqual(url.absoluteString, "https://pubapi.registry.google/rdap/domain/example.dev")
    }

    func testBootstrapNormalisesTrailingSlashes() throws {
        // One service ends in "/" and another does not; both must produce a
        // single separator.
        XCTAssertEqual(
            try bootstrap().queryURL(for: "a.com")?.absoluteString,
            "https://rdap.verisign.com/com/v1/domain/a.com"
        )
        XCTAssertEqual(
            try bootstrap().queryURL(for: "a.tools")?.absoluteString,
            "https://rdap.identitydigital.services/rdap/domain/a.tools"
        )
    }

    func testTLDWithoutRDAPYieldsNoURL() throws {
        // .io and .sh publish no RDAP service; that is a WHOIS fallback, not an
        // error — and definitely not "available".
        XCTAssertNil(try bootstrap().queryURL(for: "example.io"))
        XCTAssertFalse(try bootstrap().hasService(forTLD: "io"))
    }

    func testTLDLookupIsCaseInsensitive() throws {
        XCTAssertNotNil(try bootstrap().queryURL(for: "EXAMPLE.COM".lowercased()))
        XCTAssertTrue(try bootstrap().hasService(forTLD: "COM"))
    }

    func testMalformedBootstrapThrows() {
        XCTAssertThrowsError(try RDAPBootstrap(json: Data("not json".utf8)))
        XCTAssertThrowsError(try RDAPBootstrap(json: Data(#"{"services":[]}"#.utf8)))
    }

    // MARK: - RDAP Responses

    private let rdapBody = Data("""
    {
      "objectClassName": "domain",
      "ldhName": "EXAMPLE.COM",
      "events": [
        {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
        {"eventAction": "expiration",   "eventDate": "2028-09-14T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2019-09-09T15:39:04Z"}
      ],
      "nameservers": [
        {"ldhName": "NS2.EXAMPLE.COM"},
        {"ldhName": "NS1.EXAMPLE.COM"}
      ],
      "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Not The Registrar"]]]},
        {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                          ["fn", {}, "text", "MarkMonitor Inc."]]]}
      ]
    }
    """.utf8)

    func testRDAPExtractsRegistrationAndExpiry() {
        let status = RDAPResponse.status(from: rdapBody, domain: "example.com")
        XCTAssertEqual(status.availability, .registered)
        XCTAssertEqual(status.source, .rdap)

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        XCTAssertEqual(formatter.string(from: try! XCTUnwrap(status.registered)), "1997-09-15")
        XCTAssertEqual(formatter.string(from: try! XCTUnwrap(status.expires)), "2028-09-14")
    }

    func testRDAPPicksTheRegistrarEntityNotTheFirstOne() {
        // The abuse contact also has an "fn"; matching on roles is what keeps
        // the wrong name out.
        XCTAssertEqual(RDAPResponse.status(from: rdapBody, domain: "example.com").registrar, "MarkMonitor Inc.")
    }

    func testRDAPNameserversAreLowercasedAndSorted() {
        XCTAssertEqual(
            RDAPResponse.status(from: rdapBody, domain: "example.com").nameservers,
            ["ns1.example.com", "ns2.example.com"]
        )
    }

    func testRDAPToleratesAnEmptyBody() {
        // Registries redact heavily; a sparse 200 still means registered.
        let status = RDAPResponse.status(from: Data("{}".utf8), domain: "x.com")
        XCTAssertEqual(status.availability, .registered)
        XCTAssertNil(status.registered)
        XCTAssertTrue(status.nameservers.isEmpty)
    }

    func testDateParsingHandlesTheFormatsRegistriesActuallySend() {
        for value in [
            "2028-09-14T04:00:00Z",
            "2028-09-14T04:00:00.123Z",
            "2028-09-14T04:00:00+02:00",
            "2028-09-14 04:00:00",
            "2028-09-14",
        ] {
            XCTAssertNotNil(RDAPResponse.parseDate(value), "failed on \(value)")
        }
        XCTAssertNil(RDAPResponse.parseDate("not a date"))
    }

    // MARK: - WHOIS Interpretation

    func testWhoisNotFoundMeansAvailable() {
        for body in [
            "No match for \"NOTHERE.IO\".",
            "NOT FOUND",
            "Domain not found.",
            "No Data Found",
            "Status: AVAILABLE",
        ] {
            let status = WhoisResponse.status(from: body, domain: "nothere.io", server: "whois.nic.io")
            XCTAssertEqual(status.availability, .available, "failed on \(body)")
            XCTAssertEqual(status.source, .whois)
        }
    }

    func testWhoisRegistrationDataMeansRegistered() {
        let body = """
        Domain Name: EXAMPLE.IO
        Registry Expiry Date: 2027-01-29T10:21:56Z
        Creation Date: 2021-01-29T10:21:56Z
        Registrar: Gandi SAS
        Name Server: NS2.GANDI.NET
        Name Server: NS1.GANDI.NET
        """
        let status = WhoisResponse.status(from: body, domain: "example.io", server: "whois.nic.io")

        XCTAssertEqual(status.availability, .registered)
        XCTAssertEqual(status.registrar, "Gandi SAS")
        XCTAssertEqual(status.nameservers, ["ns1.gandi.net", "ns2.gandi.net"])
        XCTAssertNotNil(status.registered)
        XCTAssertNotNil(status.expires)
    }

    func testWhoisCommentaryDoesNotTriggerAFalseAvailable() {
        // Registry preambles routinely contain the phrase "No match" in their
        // legal boilerplate. Matching it there would report every domain free.
        let body = """
        % This server returns "No match" when a domain is not registered.
        # Terms of use apply.
        Domain Name: TAKEN.IO
        Creation Date: 2020-01-01T00:00:00Z
        """
        XCTAssertEqual(
            WhoisResponse.status(from: body, domain: "taken.io", server: "whois.nic.io").availability,
            .registered
        )
    }

    func testWhoisWithNeitherSignalIsUnknownNotAvailable() {
        // The expensive mistake is guessing "available". Silence means unknown.
        let status = WhoisResponse.status(
            from: "Please query the RRP server.\nThis TLD has no whois server.",
            domain: "mystery.zz",
            server: "whois.example"
        )
        XCTAssertEqual(status.availability, .unknown)
        XCTAssertNotNil(status.reason)
    }

    func testWhoisFieldExtractionIsCaseInsensitiveAndTrims() {
        let body = "  Registrar:   Example Registrar Ltd.  \nDomain Name: x.io"
        XCTAssertEqual(WhoisResponse.value(in: body, keys: ["registrar"]), "Example Registrar Ltd.")
    }

    func testWhoisValueIgnoresUnrelatedKeys() {
        let body = "Registrar URL: https://example.com\nDomain Name: x.io"
        // "registrar url" must not satisfy a lookup for "registrar".
        XCTAssertNil(WhoisResponse.value(in: body, keys: ["registrar"]))
    }

    // MARK: - Input Normalisation

    func testNormaliseAcceptsPlainDomains() throws {
        XCTAssertEqual(try DomainCheck.normalise("Example.COM"), "example.com")
        XCTAssertEqual(try DomainCheck.normalise("  sub.example.co.uk  "), "sub.example.co.uk")
    }

    func testNormaliseStripsWhatABrowserGivesYou() throws {
        XCTAssertEqual(try DomainCheck.normalise("https://example.com/path?q=1"), "example.com")
        XCTAssertEqual(try DomainCheck.normalise("http://example.com"), "example.com")
        XCTAssertEqual(try DomainCheck.normalise("user@example.com"), "example.com")
        XCTAssertEqual(try DomainCheck.normalise("example.com."), "example.com")
    }

    func testNormaliseRejectsNonDomains() {
        for bad in ["", "   ", "localhost", "no_underscores.com", "-lead.com", "trail-.com",
                    "spaces here.com", "double..dot.com"] {
            XCTAssertThrowsError(try DomainCheck.normalise(bad), "should reject \(bad)")
        }
    }

    func testNormaliseRejectsOverlongLabelsAndNames() {
        XCTAssertThrowsError(try DomainCheck.normalise(String(repeating: "a", count: 64) + ".com"))
        XCTAssertThrowsError(
            try DomainCheck.normalise(
                Array(repeating: String(repeating: "a", count: 60), count: 5).joined(separator: ".") + ".com"
            )
        )
    }

    func testTLDExtraction() {
        XCTAssertEqual(DomainCheck.tld(of: "a.b.co.uk"), "uk")
        XCTAssertEqual(DomainCheck.tld(of: "example.dev"), "dev")
    }

    // MARK: - Throttle

    func testThrottleSpacesRepeatCallsToOneServer() async {
        let throttle = RegistryThrottle(interval: 0.15)
        let start = Date()
        for _ in 0..<3 { await throttle.reserve("rdap.example") }
        XCTAssertGreaterThan(Date().timeIntervalSince(start), 0.25)
    }

    func testThrottleDoesNotDelayDifferentServers() async {
        // Registries limit independently; queueing them together would make a
        // multi-TLD run needlessly serial.
        let throttle = RegistryThrottle(interval: 0.5)
        let start = Date()
        for server in ["a.example", "b.example", "c.example"] { await throttle.reserve(server) }
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.3)
    }

    func testZeroIntervalDisablesThrottling() async {
        let throttle = RegistryThrottle(interval: 0)
        let start = Date()
        for _ in 0..<20 { await throttle.reserve("same") }
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.2)
    }

    // MARK: - Status

    func testDaysUntilExpiryIsComputedFromAnInjectedDate() {
        let formatter = ISO8601DateFormatter()
        let status = DomainStatus(
            domain: "x.com", availability: .registered, source: .rdap,
            expires: formatter.date(from: "2026-09-08T00:00:00Z")
        )
        let now = formatter.date(from: "2026-08-09T00:00:00Z")!
        XCTAssertEqual(status.daysUntilExpiry(from: now), 30)
    }

    func testNoExpiryYieldsNoCountdown() {
        let status = DomainStatus(domain: "x.com", availability: .available, source: .rdap)
        XCTAssertNil(status.daysUntilExpiry())
    }

    func testStatusEncodesToStableJSON() throws {
        let status = DomainStatus(domain: "x.com", availability: .available, source: .rdap)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try JSONEncoder().encode(status)) as? [String: Any]
        )
        XCTAssertEqual(object["availability"] as? String, "available")
        XCTAssertEqual(object["source"] as? String, "rdap")
    }

    // MARK: - Batch Behaviour

    func testInvalidInputInABatchDoesNotDiscardTheRest() async throws {
        // One typo in a list of two hundred must not throw away the rest.
        var configuration = DomainCheck.Configuration(useWhois: false)
        configuration.bootstrapProvider = { [json = bootstrapJSON] in json }

        var seen: [String: Availability] = [:]
        for try await status in DomainCheck.check(["not a domain", "another bad one"], configuration: configuration) {
            seen[status.domain] = status.availability
        }

        XCTAssertEqual(seen.count, 2)
        XCTAssertTrue(seen.values.allSatisfy { $0 == .unknown })
    }

    func testUnsupportedTLDIsUnknownWhenWhoisIsDisabled() async throws {
        var configuration = DomainCheck.Configuration(useWhois: false)
        configuration.bootstrapProvider = { [json = bootstrapJSON] in json }

        var results: [DomainStatus] = []
        for try await status in DomainCheck.check(["example.io"], configuration: configuration) {
            results.append(status)
        }

        XCTAssertEqual(results.first?.availability, .unknown)
        XCTAssertEqual(results.first?.source, StatusSource.none)
        XCTAssertTrue(results.first?.reason?.contains("no RDAP service") ?? false)
    }

    func testBootstrapFailureFailsTheWholeRun() async {
        // Without the bootstrap there is no authoritative server for any TLD, so
        // continuing would mean guessing.
        var configuration = DomainCheck.Configuration()
        configuration.bootstrapProvider = { throw DomainCheckError.bootstrapUnavailable("offline") }

        do {
            for try await _ in DomainCheck.check(["example.com"], configuration: configuration) {}
            XCTFail("expected the run to fail")
        } catch {
            XCTAssertEqual(error as? DomainCheckError, .bootstrapUnavailable("offline"))
        }
    }

    // MARK: - WHOIS Referrals

    func testReferralServerIsFoundInEitherSpelling() {
        XCTAssertEqual(
            WhoisResponse.referralServer(in: "Registrar WHOIS Server: whois.gandi.net"),
            "whois.gandi.net"
        )
        XCTAssertEqual(
            WhoisResponse.referralServer(in: "ReferralServer: whois://whois.markmonitor.com"),
            "whois.markmonitor.com"
        )
        XCTAssertNil(WhoisResponse.referralServer(in: "Domain Name: x.io"))
    }

    func testRegistryStaysAuthoritativeOnExistenceWhenMerging() {
        // The registrar fills gaps; it never overturns the registry's verdict.
        let registry = DomainStatus(domain: "x.io", availability: .registered, source: .whois)
        let detail = DomainStatus(
            domain: "x.io", availability: .available, source: .whois,
            registered: Date(timeIntervalSince1970: 0), registrar: "Gandi SAS",
            nameservers: ["ns1.gandi.net"]
        )

        let merged = WhoisResponse.merging(registry: registry, registrar: detail)
        XCTAssertEqual(merged.availability, .registered)
        XCTAssertEqual(merged.registrar, "Gandi SAS")
        XCTAssertEqual(merged.nameservers, ["ns1.gandi.net"])
    }

    func testMergePrefersRegistryValuesWhereItHasThem() {
        let registry = DomainStatus(
            domain: "x.io", availability: .registered, source: .whois,
            registrar: "Registry Says", nameservers: ["a.io"]
        )
        let detail = DomainStatus(
            domain: "x.io", availability: .registered, source: .whois,
            registrar: "Registrar Says", nameservers: ["b.io"]
        )
        let merged = WhoisResponse.merging(registry: registry, registrar: detail)
        XCTAssertEqual(merged.registrar, "Registry Says")
        XCTAssertEqual(merged.nameservers, ["a.io"])
    }

    func testThinRegistryResponseIsStillRegistered() {
        // .io's registry answers with nameservers and nothing else.
        let body = """
        domain:       AGENTIC.IO
        nserver:      A0.NIC.IO 65.22.160.17
        Registrar WHOIS Server: whois.gandi.net
        """
        let status = WhoisResponse.status(from: body, domain: "agentic.io", server: "whois.nic.io")
        XCTAssertEqual(status.availability, .registered)
        XCTAssertEqual(WhoisResponse.referralServer(in: body), "whois.gandi.net")
    }
}
