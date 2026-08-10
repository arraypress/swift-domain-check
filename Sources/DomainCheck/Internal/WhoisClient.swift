//
//  WhoisClient.swift
//  DomainCheck
//
//  Created by David Sherlock on 2026.
//
//  Port-43 WHOIS, for the ~100 TLDs that publish no RDAP service — `.io` and
//  `.sh` among them.
//
//  Raw POSIX sockets rather than Network.framework so this target keeps working
//  on Linux. The protocol is trivial: connect, send "<query>\r\n", read until
//  the server closes.
//

import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum WhoisClient {

    /// IANA's own WHOIS server, which reports the delegated server for a TLD.
    static let ianaServer = "whois.iana.org"

    // MARK: Query

    /// Sends one WHOIS query and returns the raw response.
    ///
    /// The blocking socket work runs off the cooperative pool — occupying a
    /// concurrency thread for the length of a network round trip would starve
    /// everything else in a bulk run.
    static func query(
        _ term: String,
        server: String,
        timeout: TimeInterval
    ) async throws(DomainCheckError) -> String {
        do {
            return try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    do {
                        continuation.resume(returning: try blockingQuery(term, server: server, timeout: timeout))
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        } catch let error as DomainCheckError {
            throw error
        } catch {
            throw .networkError(String(describing: error))
        }
    }

    /// The WHOIS server delegated for a TLD, per IANA.
    ///
    /// Resolved rather than guessed. `whois.nic.<tld>` is the common pattern but
    /// far from universal, and guessing wrong yields no answer at all.
    static func serverForTLD(_ tld: String, timeout: TimeInterval) async throws(DomainCheckError) -> String? {
        let response = try await query(tld, server: ianaServer, timeout: timeout)
        for line in response.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.lowercased().hasPrefix("whois:") else { continue }
            let value = trimmed.dropFirst("whois:".count).trimmingCharacters(in: .whitespaces)
            if !value.isEmpty { return value }
        }
        return nil
    }

    // MARK: Socket

    private static func blockingQuery(
        _ term: String,
        server: String,
        timeout: TimeInterval
    ) throws -> String {
        var hints = addrinfo(
            ai_flags: 0,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )

        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(server, "43", &hints, &info) == 0, let resolved = info else {
            throw DomainCheckError.networkError("Could not resolve \(server)")
        }
        defer { freeaddrinfo(info) }

        // Try each resolved address; a server may publish an unreachable AAAA.
        var lastError = "no address"
        var candidate: UnsafeMutablePointer<addrinfo>? = resolved

        while let address = candidate {
            defer { candidate = address.pointee.ai_next }

            let handle = socket(address.pointee.ai_family, address.pointee.ai_socktype, address.pointee.ai_protocol)
            guard handle >= 0 else { lastError = "socket() failed"; continue }

            var window = timeval(
                tv_sec: Int(timeout),
                tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000)
            )
            setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, &window, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(handle, SOL_SOCKET, SO_SNDTIMEO, &window, socklen_t(MemoryLayout<timeval>.size))

            guard connect(handle, address.pointee.ai_addr, address.pointee.ai_addrlen) == 0 else {
                close(handle)
                lastError = "connect to \(server):43 failed"
                continue
            }
            defer { close(handle) }

            let request = Array("\(term)\r\n".utf8)
            var sent = 0
            while sent < request.count {
                let wrote = request.withUnsafeBytes { buffer in
                    send(handle, buffer.baseAddress!.advanced(by: sent), request.count - sent, 0)
                }
                guard wrote > 0 else { throw DomainCheckError.networkError("Write to \(server) failed") }
                sent += wrote
            }

            var response = Data()
            var chunk = [UInt8](repeating: 0, count: 8192)
            while true {
                let read = recv(handle, &chunk, chunk.count, 0)
                if read > 0 {
                    response.append(contentsOf: chunk[0..<read])
                    // A misbehaving server that never closes must not hang a run.
                    if response.count > 512 * 1024 { break }
                } else if read == 0 {
                    break
                } else {
                    // A timeout after partial data still yields a usable answer.
                    if !response.isEmpty { break }
                    throw DomainCheckError.networkError("Read from \(server) timed out")
                }
            }

            return String(decoding: response, as: UTF8.self)
        }

        throw DomainCheckError.networkError(lastError)
    }
}
