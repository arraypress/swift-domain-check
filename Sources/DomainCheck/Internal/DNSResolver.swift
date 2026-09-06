//
//  DNSResolver.swift
//  DomainCheck
//
//  Created by David Sherlock @ ArrayPress
//
//  DNS through `dnssd`, the system resolver — the same one every other
//  process on the machine uses, so what comes back here is what the machine
//  would actually act on, cache and all. No dependency, no shelling out to
//  `dig`, and it works headless.
//
//  The records arrive as WIRE FORMAT, not text. An A record is four raw
//  bytes; TXT is a run of length-prefixed chunks; MX, NS and CNAME are
//  length-prefixed label sequences with MX carrying a two-byte preference
//  first. Reading them as strings gives plausible-looking rubbish.
//

import Foundation
import dnssd

/// Looks names up through the system resolver.
enum DNSResolver {

    /// Collects the values from one query. A class because the C callback
    /// gets an opaque pointer, not a closure capture.
    private final class Collector {
        var values: [String] = []
        var finished = false
    }

    /// Every value of one record type for a name.
    ///
    /// - Parameters:
    ///   - domain: The name to ask about.
    ///   - type: Which record type.
    ///   - timeout: How long to wait before giving up.
    /// - Returns: The values, in the order the resolver gave them.
    static func query(_ domain: String, type: DNSRecordType,
                      timeout: TimeInterval = 3) -> [String] {
        let collector = Collector()
        var service: DNSServiceRef?

        let callback: DNSServiceQueryRecordReply = { _, flags, _, error, _, rrtype, _, length, data, _, context in
            guard let context else { return }
            let collector = Unmanaged<Collector>.fromOpaque(context).takeUnretainedValue()
            if flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) == 0 { collector.finished = true }
            guard error == kDNSServiceErr_NoError, let data, length > 0 else { return }
            let bytes = UnsafeRawBufferPointer(start: data, count: Int(length))
            // Fully qualified: an unqualified call to a static member counts as
            // capturing context, and a C function pointer cannot capture.
            collector.values.append(contentsOf: DNSResolver.decode(bytes, rrtype: rrtype))
        }

        let context = Unmanaged.passUnretained(collector).toOpaque()
        let status = DNSServiceQueryRecord(&service, 0, 0, domain, type.code,
                                           UInt16(kDNSServiceClass_IN), callback, context)
        guard status == kDNSServiceErr_NoError, let service else { return [] }
        defer { DNSServiceRefDeallocate(service) }

        let descriptor = DNSServiceRefSockFD(service)
        guard descriptor >= 0 else { return [] }
        let deadline = Date().addingTimeInterval(timeout)

        while Date() < deadline, !collector.finished {
            var readable = fd_set()
            __darwin_fd_set(descriptor, &readable)
            var wait = timeval(tv_sec: 0, tv_usec: 100_000)
            guard select(descriptor + 1, &readable, nil, nil, &wait) > 0 else { continue }
            guard DNSServiceProcessResult(service) == kDNSServiceErr_NoError else { break }
        }
        return collector.values
    }

    /// Turns one record's wire bytes into text.
    ///
    /// - Parameters:
    ///   - bytes: The record's data, as the resolver gave it.
    ///   - rrtype: Its numeric type.
    /// - Returns: The values it holds.
    static func decode(_ bytes: UnsafeRawBufferPointer, rrtype: UInt16) -> [String] {
        switch rrtype {
        case UInt16(kDNSServiceType_A):
            guard bytes.count == 4 else { return [] }
            return [bytes.map(String.init).joined(separator: ".")]

        case UInt16(kDNSServiceType_AAAA):
            guard bytes.count == 16 else { return [] }
            let groups = stride(from: 0, to: 16, by: 2).map {
                String(format: "%x", Int(bytes[$0]) << 8 | Int(bytes[$0 + 1]))
            }
            return [groups.joined(separator: ":")]

        case UInt16(kDNSServiceType_TXT):
            // A run of length-prefixed chunks; long records are split across
            // several and a reader that takes only the first loses the rest.
            var values: [String] = []
            var index = 0
            while index < bytes.count {
                let length = Int(bytes[index])
                index += 1
                guard length > 0, index + length <= bytes.count else { break }
                let chunk = Data(bytes[index..<(index + length)])
                if let text = String(data: chunk, encoding: .utf8) { values.append(text) }
                index += length
            }
            return values

        case UInt16(kDNSServiceType_MX), UInt16(kDNSServiceType_NS), UInt16(kDNSServiceType_CNAME):
            // MX puts a two-byte preference before the name.
            let start = rrtype == UInt16(kDNSServiceType_MX) ? 2 : 0
            return [name(in: bytes, from: start)].filter { !$0.isEmpty }

        default:
            return []
        }
    }

    /// Reads a length-prefixed label sequence — `5apple3com0` — as a name.
    static func name(in bytes: UnsafeRawBufferPointer, from start: Int) -> String {
        var labels: [String] = []
        var index = start
        while index < bytes.count, bytes[index] != 0 {
            let length = Int(bytes[index])
            // 0xC0 and above marks a compression pointer, which cannot be
            // followed without the whole message. Stop rather than read the
            // pointer's bytes as text.
            guard length < 64, index + 1 + length <= bytes.count else { break }
            index += 1
            let chunk = Data(bytes[index..<(index + length)])
            labels.append(String(data: chunk, encoding: .utf8) ?? "")
            index += length
        }
        return labels.joined(separator: ".")
    }
}
