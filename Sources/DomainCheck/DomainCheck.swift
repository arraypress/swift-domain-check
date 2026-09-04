//
//  DomainCheck.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//
//  Domain availability, without an API key.
//

import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Checks whether domains can be registered.
///
/// ```swift
/// let status = try await DomainCheck.check("example.dev")
/// print(status.availability)          // .registered
/// print(status.expires ?? "")
///
/// for try await status in DomainCheck.check(["a.dev", "b.com", "c.io"]) {
///     if status.availability == .available { print(status.domain) }
/// }
/// ```
///
/// ## How an answer is reached
///
/// 1. Resolve the TLD's authoritative RDAP service from IANA's bootstrap.
/// 2. Query it. `404` means available; `200` means registered.
/// 3. If the TLD publishes no RDAP service — `.io` and `.sh` among roughly a
///    hundred — fall back to port-43 WHOIS.
/// 4. If neither can answer, report ``Availability/unknown`` rather than guess.
///
/// ## What this deliberately does not do
///
/// It never treats DNS as evidence of availability. A registered domain with no
/// nameservers resolves to nothing, so "no DNS record" and "unregistered" look
/// identical — and reading the first as the second is how a checker tells
/// someone a taken name is free.
public enum DomainCheck {

    // MARK: - Configuration

    /// Networking and politeness options.
    public struct Configuration: Sendable {

        /// Per-request timeout, in seconds.
        public var timeout: TimeInterval

        /// How many domains to check at once.
        public var maxConcurrent: Int

        /// Minimum gap between requests to the *same* registry, in seconds.
        public var perRegistryInterval: TimeInterval

        /// How many times to retry after a `429`.
        public var maxRetries: Int

        /// Whether to keep the record the source sent, verbatim.
        ///
        /// Off by default: RDAP bodies are several kilobytes each and a run
        /// over a hundred candidate names does not want a hundred of them.
        public var keepRecord: Bool

        /// Whether to fall back to WHOIS for TLDs with no RDAP service.
        ///
        /// Turning this off makes a run faster and entirely structured, at the
        /// cost of ``Availability/unknown`` for `.io`, `.sh` and similar.
        public var useWhois: Bool

        /// Supplies IANA's `dns.json`.
        ///
        /// Injectable so a caller can cache it — it changes rarely and is ~70 KB,
        /// which is wasteful to refetch on every invocation — and so tests can
        /// run without network access.
        public var bootstrapProvider: @Sendable () async throws -> Data

        public init(
            timeout: TimeInterval = 20,
            maxConcurrent: Int = 8,
            perRegistryInterval: TimeInterval = 0.35,
            maxRetries: Int = 2,
            useWhois: Bool = true,
            keepRecord: Bool = false,
            bootstrapProvider: (@Sendable () async throws -> Data)? = nil
        ) {
            self.timeout = timeout
            self.maxConcurrent = maxConcurrent
            self.perRegistryInterval = perRegistryInterval
            self.maxRetries = maxRetries
            self.useWhois = useWhois
            self.keepRecord = keepRecord
            self.bootstrapProvider = bootstrapProvider ?? Configuration.fetchBootstrap
        }

        public static var `default`: Configuration { Configuration() }

        /// The IANA RDAP bootstrap registry.
        public static let bootstrapURL = URL(string: "https://data.iana.org/rdap/dns.json")!

        @Sendable
        static func fetchBootstrap() async throws -> Data {
            do {
                let (data, _) = try await URLSession.shared.data(from: bootstrapURL)
                return data
            } catch {
                throw DomainCheckError.bootstrapUnavailable(error.localizedDescription)
            }
        }
    }

    // MARK: - Checking

    /// Checks one domain.
    ///
    /// - Parameters:
    ///   - domain: A domain name, e.g. `"example.dev"`.
    ///   - configuration: Networking and politeness options.
    /// - Throws: ``DomainCheckError`` when no determination could be attempted.
    ///   A domain being taken is a result, not an error.
    public static func check(
        _ domain: String,
        configuration: Configuration = .default
    ) async throws -> DomainStatus {
        let normalised = try normalise(domain)
        let bootstrap = try await loadBootstrap(configuration)
        let throttle = RegistryThrottle(interval: configuration.perRegistryInterval)
        return await check(normalised, bootstrap: bootstrap, throttle: throttle, configuration: configuration)
    }

    /// Checks many domains, yielding each result as it lands.
    ///
    /// Results arrive out of order — a `.com` served by a fast registry should
    /// not wait behind a slow WHOIS lookup for a `.sh`.
    public static func check(
        _ domains: [String],
        configuration: Configuration = .default
    ) -> AsyncThrowingStream<DomainStatus, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let bootstrap = try await loadBootstrap(configuration)
                    let throttle = RegistryThrottle(interval: configuration.perRegistryInterval)

                    // Invalid input is reported per-domain rather than failing the
                    // batch: one typo in a list of two hundred should not discard
                    // the other hundred and ninety-nine.
                    let prepared: [Result<String, DomainCheckError>] = domains.map { input in
                        do { return .success(try normalise(input)) }
                        catch let error as DomainCheckError { return .failure(error) }
                        catch { return .failure(.invalidDomain(input)) }
                    }

                    try await withThrowingTaskGroup(of: DomainStatus.self) { group in
                        var index = 0
                        let limit = max(1, configuration.maxConcurrent)

                        func addNext() -> Bool {
                            while index < prepared.count {
                                let entry = prepared[index]
                                index += 1
                                switch entry {
                                case .failure(let error):
                                    continuation.yield(
                                        DomainStatus(
                                            domain: domains[index - 1].lowercased(),
                                            availability: .unknown,
                                            source: .none,
                                            reason: error.errorDescription
                                        )
                                    )
                                case .success(let domain):
                                    group.addTask {
                                        await check(
                                            domain, bootstrap: bootstrap,
                                            throttle: throttle, configuration: configuration
                                        )
                                    }
                                    return true
                                }
                            }
                            return false
                        }

                        for _ in 0..<limit where addNext() {}

                        while let status = try await group.next() {
                            continuation.yield(status)
                            _ = addNext()
                        }
                    }

                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    // MARK: - Engine

    private static func check(
        _ domain: String,
        bootstrap: RDAPBootstrap,
        throttle: RegistryThrottle,
        configuration: Configuration
    ) async -> DomainStatus {
        if let url = bootstrap.queryURL(for: domain) {
            do {
                return try await queryRDAP(url: url, domain: domain, throttle: throttle, configuration: configuration)
            } catch {
                // A registry that will not answer is not evidence of anything.
                return DomainStatus(
                    domain: domain, availability: .unknown, source: .rdap,
                    reason: error.errorDescription
                )
            }
        }

        guard configuration.useWhois else {
            return DomainStatus(
                domain: domain, availability: .unknown, source: .none,
                reason: "no RDAP service for .\(tld(of: domain)) and WHOIS is disabled"
            )
        }

        return await queryWhois(domain: domain, throttle: throttle, configuration: configuration)
    }

    /// Queries an RDAP service, retrying while it says to back off.
    private static func queryRDAP(
        url: URL,
        domain: String,
        throttle: RegistryThrottle,
        configuration: Configuration
    ) async throws(DomainCheckError) -> DomainStatus {
        let host = url.host ?? "rdap"

        for attempt in 0...configuration.maxRetries {
            await throttle.reserve(host)

            var request = URLRequest(url: url)
            request.timeoutInterval = configuration.timeout
            request.setValue("application/rdap+json", forHTTPHeaderField: "Accept")

            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await URLSession.shared.data(for: request)
            } catch {
                throw DomainCheckError.networkError(error.localizedDescription)
            }

            guard let http = response as? HTTPURLResponse else {
                throw DomainCheckError.parsingError("no HTTP response from \(host)")
            }

            switch http.statusCode {
            case 200:
                return RDAPResponse.status(from: data, domain: domain, keepingRecord: configuration.keepRecord)

            case 404:
                // Authoritative: this registry has no record of the name.
                return DomainStatus(domain: domain, availability: .available, source: .rdap)

            case 429, 503:
                let retryAfter = http.value(forHTTPHeaderField: "Retry-After").flatMap(Double.init) ?? 2
                await throttle.penalise(host, seconds: retryAfter)
                if attempt == configuration.maxRetries {
                    throw DomainCheckError.rateLimited(server: host)
                }

            default:
                throw DomainCheckError.networkError("HTTP \(http.statusCode) from \(host)")
            }
        }

        throw DomainCheckError.rateLimited(server: host)
    }

    /// Resolves the TLD's WHOIS server via IANA, then asks it.
    private static func queryWhois(
        domain: String,
        throttle: RegistryThrottle,
        configuration: Configuration
    ) async -> DomainStatus {
        let suffix = tld(of: domain)
        do {
            await throttle.reserve(WhoisClient.ianaServer)
            guard let server = try await WhoisClient.serverForTLD(suffix, timeout: configuration.timeout) else {
                return DomainStatus(
                    domain: domain, availability: .unknown, source: .none,
                    reason: "IANA lists no WHOIS server for .\(suffix)"
                )
            }

            await throttle.reserve(server)
            let response = try await WhoisClient.query(domain, server: server, timeout: configuration.timeout)
            let status = WhoisResponse.status(from: response, domain: domain, server: server, keepingRecord: configuration.keepRecord)

            // Thin registries confirm existence but hold no dates or registrar
            // name; those live with the registrar it refers us to. Only worth a
            // second round trip when the domain exists and detail is missing.
            guard status.availability == .registered,
                  status.registered == nil || status.registrar == nil,
                  let referral = WhoisResponse.referralServer(in: response),
                  referral.lowercased() != server.lowercased()
            else { return status }

            await throttle.reserve(referral)
            guard let detail = try? await WhoisClient.query(
                domain, server: referral, timeout: configuration.timeout
            ) else {
                // The registrar being unreachable costs detail, not correctness.
                return status
            }

            return WhoisResponse.merging(
                registry: status,
                registrar: WhoisResponse.status(from: detail, domain: domain, server: referral, keepingRecord: configuration.keepRecord)
            )
        } catch {
            return DomainStatus(
                domain: domain, availability: .unknown, source: .whois,
                reason: error.errorDescription
            )
        }
    }

    // MARK: - Bootstrap

    private static func loadBootstrap(_ configuration: Configuration) async throws -> RDAPBootstrap {
        let data: Data
        do {
            data = try await configuration.bootstrapProvider()
        } catch let error as DomainCheckError {
            throw error
        } catch {
            throw DomainCheckError.bootstrapUnavailable(error.localizedDescription)
        }
        return try RDAPBootstrap(json: data)
    }

    // MARK: - Input

    /// Validates and lowercases a domain.
    static func normalise(_ input: String) throws(DomainCheckError) -> String {
        var value = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        // Accept a pasted URL, since that is what a browser hands you.
        if let range = value.range(of: "://") {
            value = String(value[range.upperBound...])
        }
        if let slash = value.firstIndex(of: "/") {
            value = String(value[..<slash])
        }
        if let at = value.lastIndex(of: "@") {
            value = String(value[value.index(after: at)...])
        }
        while value.hasSuffix(".") { value.removeLast() }

        guard !value.isEmpty, value.count <= 253 else { throw .invalidDomain(input) }

        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { throw .invalidDomain(input) }

        for label in labels {
            guard (1...63).contains(label.count),
                  !label.hasPrefix("-"), !label.hasSuffix("-"),
                  label.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" })
            else { throw .invalidDomain(input) }
        }

        return value
    }

    /// The final label of a domain.
    static func tld(of domain: String) -> String {
        domain.split(separator: ".").last.map(String.init) ?? ""
    }
}
