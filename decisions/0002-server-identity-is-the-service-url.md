# 0002: A server is identified by its service URL, and a Space by its own URL

- Status: accepted (2026-10-28; the was-client conventions are implemented in
  was-client 0.100.0, and the wallet-side conventions below were settled by the
  maintainer the same day)
- Date: 2026-10-27 (amended 2026-10-28)
- Driving work: the cleanup of the dcw connections-directory change, which found
  every consumer appending `/spaces/` to a stored server base URL, and the spec
  reading that followed.
- Affects: `@interop/was-client` (`WasClient`, `paths`, `internal/service`,
  `grant`, `testing`), `@interop/wallet-core` (the did:webvh template and its
  inverse, `verifyAccountLog`, the keyring account pointer, `AccountLogPointer`,
  every `storageServerUrl` / `wasServerUrl` / `host` parameter, the `was-link`
  payload), `@interop/wallet-request` (`WalletOnboardingQuery`), freewallet
  (config, `wasClientAt`, the keyring pointer, `didWeb.ts`), dcw
  (`profile_sync`, `WAS.BASE_URL`, the sync modules), was-teaching-server (the
  testing counterpart), and the Portable Web Spaces spec (Reading This Document,
  the did:webvh controller text).

## Context

The Portable Web Spaces spec makes the service description the root of the URL
graph. A server may be mounted under any path of an origin. Every URL the
description carries is absolute. The Spaces Repository (`/spaces/`) is optional.
The spec states that a client cannot derive the server root from a URL it holds.
Nothing in it requires `/space/{id}/` to sit beside `/spaces/` under one root,
and a single-tenant server has no `/spaces/` at all.

The ecosystem assumed otherwise. was-client 0.99 takes the Spaces URL as
`serverUrl`, strips its final `spaces` segment to get a `baseUrl`, and assembles
every Space, collection, resource, and `did.jsonl` URL, and every zcap
`invocationTarget`, beneath that base. wallet-core, freewallet, and dcw store
the base (as `host`, `storageServerUrl`, `wasServerUrl`,
`profile_sync.serverUrl`) and call `spacesUrl({ baseUrl })` at every client
construction. `verifyAccountLog` reads a path prefix off the stored `host`
because the did:webvh the wallets mint encodes only the URL host, so the DID
cannot locate its own log under a sub-path mount.

A base URL is therefore a convention of ours, not a thing the spec defines, and
it is the single most repeated and most confused value across the repos. Two
inputs are the only ones a consumer can actually hold: the URL of the service
description, or a Spaces Repository URL (from which a HEAD request yields the
`Link: rel="service"` header). Neither yields a Space URL by string assembly.

## Decision

1. A server is identified by its service URL. `WasClient` is constructed from
   `{ serviceUrl }` or `{ spacesUrl }` (settled 2026-10-28: both arms stay on
   the constructor; a client built from `spacesUrl` discovers the service
   description through the `service` link, and the description's `spaces` member
   is not checked against the given URL, since a mismatch fails on its own),
   with an optional cached `serviceDescription`. The client exposes no
   `baseUrl`, and `spacesUrl({ baseUrl })`, `baseUrlOfSpacesUrl`, `toUrl` and
   `parseAbsoluteSpaceTarget` are removed. The `./paths` builders take
   `{ spaceUrl, ... }` and return URLs (`collectionUrl`, `resourceUrl`,
   `spaceMetaUrl`, ...).

2. A Space is identified by its own absolute URL. `createSpace` returns a handle
   built from the response's `Location`. `spaceAt(url)` opens a handle on a URL
   the caller holds. `space(spaceId)` is removed. Root capability ids and every
   collection and resource URL derive from the Space URL, as the spec's
   hierarchy defines them, and from nothing above it. The Space a capability
   belongs to is read off its delegation chain, whose root is the Space's root
   capability id (`spaceUrlOf`), so `fromCapability` and `revoke` need no base.
   A grant names the Space it is rooted in through `GrantOptions.spaceUrl` (the
   handle sugar fills it); a bare `was.grant({ target })` roots at the target's
   own root capability and is not Space-revocable (settled 2026-10-28).

3. The one derivation that remains is DID to Space URL, defined by the did:webvh
   and did:web methods rather than by this ecosystem: the identifier's colon
   segments after the host are the path, so
   `did:webvh:<SCID>:<host>:<prefix...>:space:<spaceId>:id` resolves to
   `https://<host>/<prefix>/space/<spaceId>/id/did.jsonl`, and the Space
   container is the parent of the `id` collection. wallet-core owns both the
   template that mints the DID and its inverse, and `verifyAccountLog` checks
   the fetched location against that inverse rather than against a stored base
   path.

4. Persisted and wire records carry the service URL and the DID, and no base.
   The keyring account pointer and `AccountLogPointer` become
   `{ did, spaceUrl? }`: the DID, with the Space URL as an optional cache
   (settled 2026-10-28). `WalletOnboardingQuery` carries `did` and drops `host`
   and `spaceId`; the service URL rides along as an optional `serviceUrl`
   convenience (settled 2026-10-28). dcw's `profile_sync` row stores
   `serviceUrl`, and freewallet's environment variable is `VITE_PWS_SERVICE_URL`
   (settled 2026-10-28).

5. No Space URL template is added to the service description. Every case where a
   wallet holds a `spaceId` also holds the DID; the one spec operation that
   needs a Space URL without a prior one (create by id via
   `PUT /space/{id}/meta`) is reached only by a client that was handed the URL.

## Rejected Alternatives

- A `baseUrl` constructor option, deriving the Spaces URL inside the client. The
  client has no more right to assume a `/spaces/` mount than the consumers do,
  and discovery cannot start from an origin root (often a landing page with no
  `Link` header and no CORS).
- Storing the Spaces URL in place of the base. It removes the wrapper but keeps
  the assembly of Space URLs from a root, which the spec does not grant, and it
  leaves single-tenant servers unsupported.
- A `space` URI Template member (RFC 6570 level 1) on the service description's
  version entry. Cheap to implement (`url-template` is 8 KB with no
  dependencies), but it solves a case no wallet has, and it would be a second
  thing for a server to keep consistent with its `Location` headers and DIDs.
- Keeping `host` as a base URL and encoding only the URL host in the DID, with
  the prefix recovered from the stored pointer. This is today's design. It makes
  the DID non-self-locating, which defeats the point of a did:webvh, and it is
  the reason every wallet carries a base URL at all.

## Consequences

- A breaking was-client release (0.100.0), followed by wallet-core (WC-307),
  wallet-request (WR-4), freewallet (FW-694), was-react (WR-98), and dcw
  (DCW-104); the teaching server's testing counterpart is WAS-234. The teaching
  server's testing counterpart changes its return value; the server itself
  already sends the `service` link on every response.
- Every stored account pointer, invitation QR, and dcw profile row changes
  meaning. Greenfield: no migration; test profiles and dev WAS data are
  re-created.
- Sub-path mounts become representable end to end, in the DID, the log location
  check, and the zcap targets. The teaching server does not yet support one, so
  the proof is a separate item there.
- Consumers may rely on: a `WasClient` never builds a URL above a Space; a Space
  handle's URL is byte-identical to what the server advertised; a did:webvh
  minted by wallet-core resolves to its log with no out-of-band base.
- The `did:webvh` identifier is longer for a sub-path mount, and a host
  migration (already a known case for the client-annex parser) now also covers a
  prefix change.

## Revisit Criteria

1. The spec adds a server-level member that locates Spaces by id (a template or
   a lookup endpoint). Then `spaceAt` gains a sibling that uses it, as an
   addition, not a return of `space(spaceId)`.
2. A PWS server ships whose Spaces live on a different origin from its service
   description. The DID-to-URL inverse still holds, but the "one description per
   server" caching in consumers would not.
3. did:webvh changes how path segments are encoded in the method-specific id.
   The inverse in wallet-core follows the method, so this is a wallet-core
   change, not a return to a stored base.
