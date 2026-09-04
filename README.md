# Swift Domain Check

Check whether a domain can be registered, straight from the registry. No API key, no account, no quota.

```swift
let status = try await DomainCheck.check("agenticcli.tools")
print(status.availability)          // .available

for try await status in DomainCheck.check(["a.com", "b.dev", "c.io"]) {
    if status.availability == .available { print(status.domain) }
}
```

## Features

- 🌐 **RDAP first** — the structured, authoritative protocol, across ~1,200 TLDs via IANA's bootstrap
- 📟 **WHOIS fallback** — port 43 for the ~100 TLDs with no RDAP service, `.io` and `.sh` among them
- 🚦 **Per-registry throttling** — registries rate limit independently, so a multi-TLD run stays parallel
- 📅 **Registration and expiry dates**, registrar, nameservers
- ❓ **An honest `unknown`** — never a guess
- 🔑 **No credentials** · Swift 6 · pure Foundation, Linux-friendly

## The record, not just the verdict

`DomainStatus` carries what the registry actually said: `registrar`,
`registered`, `expires`, `updated`, `nameservers`, `statuses`, `dnssec`,
`registryID` — and, with `keepRecord: true`, the source's own document.
`isLocked` and `isLapsing` answer the two questions worth asking of a taken
name: can it be transferred, and is it about to fall free.

**Status codes are normalised.** RDAP publishes them space-separated and
lowercase — `"client transfer prohibited"` — while WHOIS publishes the EPP
camelCase form with an explanatory URL after it. Both come back as
`clientTransferProhibited`, because a caller matching one spelling would
silently miss every domain answered by the other protocol.

`keepRecord` is off by default: RDAP bodies are several kilobytes each, and a
run over a hundred candidate names does not want a hundred of them.

## Installation

```swift
.package(url: "https://github.com/arraypress/swift-domain-check.git", from: "0.1.0")
```

## How an answer is reached

1. Resolve the TLD's authoritative RDAP service from [IANA's bootstrap](https://data.iana.org/rdap/dns.json).
2. Query it. `404` means available; `200` means registered.
3. No RDAP service for that TLD? Fall back to port-43 WHOIS, following the registrar referral when a thin registry gives one.
4. If neither can answer, report `.unknown`.

## The three rules that make it correct

These are not stylistic. Each one is a way to report a **registered domain as free**, which is the only truly expensive mistake a checker can make.

**A 404 counts only from the authoritative server.** The bootstrap maps TLD → service; querying any other host and reading its 404 as "available" is meaningless. Hardcoding a server is how that happens.

**DNS is never evidence of availability.** A registered domain with no nameservers resolves to nothing, so "no NS record" and "unregistered" look identical. DNS can prove *taken*; it can never prove *free*.

**Silence is `unknown`, not `available`.** WHOIS has no schema — every registry words "no such domain" differently. The parser says `.available` only on an explicit not-found phrase, `.registered` only on explicit registration data, and `.unknown` otherwise.

## Usage

```swift
// One domain
let status = try await DomainCheck.check("example.dev")
status.availability      // .available | .registered | .unknown
status.source            // .rdap | .whois | .none
status.registered        // Date?
status.expires           // Date?
status.registrar         // String?
status.nameservers       // [String]
status.reason            // why, when .unknown

status.daysUntilExpiry() // Int? — a name lapsing in 3 weeks is a different prospect
```

```swift
// Many, streamed as each registry answers
for try await status in DomainCheck.check(names) { … }
```

Results arrive out of order on purpose: a `.com` served in 80 ms should not queue behind a slow `.sh` WHOIS lookup.

## Configuration

```swift
var configuration = DomainCheck.Configuration(
    timeout: 20,
    maxConcurrent: 8,
    perRegistryInterval: 0.35,   // gap between calls to the SAME registry
    maxRetries: 2,
    useWhois: true
)

// Cache the ~70 KB bootstrap yourself; it changes on the order of weeks.
configuration.bootstrapProvider = { try myCache.data() }
```

`perRegistryInterval` is keyed per server, not globally — checking 100 names across 20 TLDs runs 20 ways in parallel and only queues behind itself per registry. Six concurrent lookups against one registry earns a `429`, which is where that default came from.

`bootstrapProvider` is injectable so callers can cache it and so tests can run with no network at all.

## Errors

A domain being taken is a **result**, not an error. `DomainCheckError` is thrown only when nothing could be determined:

| Case | Meaning |
|---|---|
| `invalidDomain` | Not a usable name |
| `bootstrapUnavailable` | No IANA registry — fatal for the run, since no TLD has a known server |
| `rateLimited` | A registry told us to back off |
| `networkError` / `parsingError` | Transport or response failure |

In a batch, a single bad name yields an `.unknown` status for that name rather than failing the run.

## Known limits

- Thin registries that publish no referral (notably `.io`) return a correct `registered` verdict with no dates or registrar.
- A handful of ccTLDs have neither RDAP nor a public WHOIS; those report `.unknown` with a reason.

## Requirements

- Swift 6.0+
- macOS 14+ / iOS 17+ (Linux-compatible: Foundation and POSIX sockets only)

## License

MIT — see [LICENSE](LICENSE).
