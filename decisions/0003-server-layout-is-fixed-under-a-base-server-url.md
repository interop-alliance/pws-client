# 0003: A server's layout is fixed under a base server URL; a fixed Space is opened by its own URL

- Status: accepted (2026-10-29; supersedes 0002)
- Date: 2026-10-29
- Driving work: implementing the wallet-core side of decision 0002 found that a
  passphrase login holds a service URL, a derived did:key and a derived Space
  id, and nothing else. Decision 0002 had assumed no consumer ever holds a Space
  id without also holding the Space's URL or a DID that resolves to it. That
  assumption was wrong, and the two spec-conformant ways out (a List Spaces
  round trip, or a URL template on the service description) both cost more than
  the convention they replaced.
- Affects: `@interop/was-client` (`WasClient`, `paths`, `internal/service`,
  `testing`), `@interop/wallet-core` (the did:webvh template and its inverse,
  `verifyAccountLog`, the keyring account pointer, the passphrase unlock Space,
  every `serviceUrl` parameter introduced under 0002), `@interop/wallet-request`
  (`WalletOnboardingQuery`), freewallet (config, `wasClientAt`), was-react
  (`wasRemoteStore`, `audienceReader`, the dev provisioning script), dcw
  (`profile_sync`, the sync modules), was-teaching-server (routing, the testing
  counterpart), and the Portable Web Spaces spec (Reading This Document, Service
  Description, Spaces Repositories, the did:webvh controller text).

## Context

The spec fixes the URL layout below a Space: `{space}/{collection_id}/`,
`{space}/{collection_id}/{resource_id}`, and `meta` at each level. Above a Space
it fixed nothing. Decision 0002 took that freedom seriously: a server may mount
`/spaces/`, `/space/{space_id}/` and the service description anywhere, so a
client must never assemble a Space URL and must obtain one from a `Location`
header, a listing, a capability chain, a DID, or out of band. was-client 0.100.0
implemented that rule and removed `baseUrl` and `space(spaceId)`.

The first consumer to port hit a case the rule cannot serve. A fresh passphrase
login derives an unlock did:key and a Space id from the passphrase and must
reach `{space}/meta` with `PUT` and if-none-match, so that create and re-run are
one idempotent request and an unknown passphrase is one 404. Under 0002 the only
ways to turn that id into a URL were a signed List Spaces call before every
login, which makes listing load-bearing for authentication, turns an idempotent
`PUT` into a `POST` with a 409 branch, and replaces a 404-masked probe with a
positive "this identity controls these Spaces" answer; or a Space URL template
on the service description, which asks every developer to fetch and expand a
template before building their first Space handle.

Meanwhile, every consumer before 0002 had assumed the same thing: the three
server-level endpoints sit beside each other under one prefix. No deployment has
ever wanted otherwise. The freedom 0002 protected was unused, and the rule it
imposed was being paid for on the hot path of login.

The single-Space case is different in kind. A personal site that is one Space
with a fixed set of collections (`https://alice.example/posts/`,
`https://alice.example/images/`) has no Space id, no Spaces Repository and no
prefix to hang peers on. It needs a client that starts from the Space URL and
nothing else.

## Decision

1. **Fixed layout above a Space.** A server that addresses Spaces by id
   publishes them under one base server URL. With `{base}` an absolute http(s)
   URL ending in `/`, the server-level endpoints are:

   - `{base}service` -- the service description;
   - `{base}spaces/` -- the Spaces Repository, when the server has one;
   - `{base}space/{space_id}/` -- a Space.

   The spec states this layout normatively in Reading This Document and in the
   Service Description and Spaces Repositories sections, replacing the text that
   forbade clients from assuming the three are peers. A client holding the base
   server URL may construct all three. The segments `service`, `spaces` and
   `space` are the permanent part of this record.

2. **`baseServerUrl` is the client's one locator for that layout.** `WasClient`
   is constructed from `{ baseServerUrl }`: an absolute http(s) URL with no
   query or fragment, to which a missing trailing slash is added rather than
   refused (settled 2026-10-29). It derives the service URL and the Spaces URL
   from it with no HEAD request and no `Link` header parsing. `space(id)`
   returns a handle on `{base}space/{id}/` synchronously. `spaceAt(url)` stays
   and is still authoritative for a URL the caller received (a `Location`
   header, a capability's invocation target through `spaceUrlOf`, a did:webvh);
   a received Space URL is never checked against the base server URL, because
   grants and DIDs may legitimately name a Space on another server.
   `createSpace` keeps returning the handle built from `Location`. The
   `serviceUrl` and `spacesUrl` constructor arms from 0002 are removed.

3. **The service description confirms the layout.** Its `url` member must equal
   `{base}service` and its `spaces` member, when present, must equal
   `{base}spaces/`. The client checks both when it reads the description and
   refuses on mismatch, so a wrong base fails with a clear error at the first
   structural request rather than with a 404 deep in a Space.

4. **A fixed Space is opened by its own URL.** For a server that is one Space
   with no id, the client offers `WasClient.forSpace({ spaceUrl, ... })` (name
   settled 2026-10-29), which takes the Space URL and nothing above it. It finds
   the service description by following the `Link: rel="service"` header on a
   HEAD of the Space URL, which is the one place the discovery mechanism of 0002
   remains load-bearing. The handle it returns is the same `Space` type as
   `space(id)` and `spaceAt(url)` produce, so code written against a handle does
   not know which entry point built it. This entry point has no
   collection-management switch: whether the server lets a client create
   collections is read from the `collection-management` feature token, as for
   every other affordance.

5. **Reserved segments at a root-mounted Space.** When a Space URL is an
   origin's root, its collections occupy the first path segment, so the spec
   adds `service`, `spaces` and `space` to the reserved segments a collection id
   must not collide with. This keeps a root-mounted Space from colliding with
   the layout in rule 1 should the operator later add a prefix.

6. **The did:webvh inverse derives the base server URL.** The identifier's colon
   segments after the host are the path, so
   `did:webvh:<SCID>:<host>:<prefix...>:space:<spaceId>:id` resolves to
   `https://<host>/<prefix>/space/<spaceId>/id/did.jsonl`, and under rule 1
   `https://<host>/<prefix>/` is the base server URL. A wallet that holds the
   DID therefore holds the base server URL and need not store one. wallet-core
   owns the template, its inverse, and the base-server-URL derivation.

7. **Persisted and wire records carry the base server URL where 0002 carried the
   service URL.** The keyring account pointer stays `{ did, spaceUrl? }`.
   `WalletOnboardingQuery` carries `did` with `baseServerUrl` as the optional
   convenience. dcw's `profile_sync` row stores `baseServerUrl`. freewallet's
   environment variable names the base server URL. The passphrase unlock Space
   is located as `{base}space/{derivedId}/` and created with `PUT .../meta` and
   if-none-match, as it was before 0002.

## Rejected Alternatives

- **Keep 0002 and locate the unlock Space through List Spaces.** Correct under
  the spec as written, but it makes the `listing` feature a precondition for
  login, costs a signed round trip per login and per keyring probe, replaces an
  idempotent `PUT` with `POST` plus a 409 branch plus a listing to recover the
  URL, and turns the pre-authentication probe from a 404-masked GET into a
  positive controller-to-Spaces oracle. It also demotes the derived Space id
  from the address to a cross-check, which defeats the reason for deriving it.
- **Keep 0002 and add a `space` URI Template to the service description.** The
  path 0002's own revisit criterion named. It solves the lookup in one request
  and keeps the server in charge of its layout. It lost on developer cost: the
  first Space handle becomes an async operation gated on a description fetch and
  a template expansion, every consumer must learn RFC 6570 to read the
  description, and the template would in practice always expand to the layout
  rule 1 fixes. A convention written once in the spec is cheaper than the same
  convention declared by every server and expanded by every client.
- **Keep both the 0002 constructor arms and add `baseUrl`.** Three ways to build
  a client, two of which cannot produce a Space from an id. The arms exist only
  to feed discovery, which rule 1 makes unnecessary, and keeping them would keep
  the "which URL do I store" confusion that drove 0002.
- **A `collectionsManagement` option on the fixed-Space entry point.** It
  duplicates the server's `collection-management` feature token and can disagree
  with it. The client already treats features as server affordances.
- **Two client classes, one per layout.** The two entry points differ only in
  where the first URL comes from; everything below a Space handle is the same.
  Separate classes would force a consumer that holds only a grant to guess the
  class before it knows what kind of server issued the grant.
- **Mandating the peer layout for root-mounted Spaces too.** A Space at an
  origin root has no parent for `service` to be a peer in. Discovery by `Link`
  header is the only mechanism that works there, and it is cheap.

## Consequences

- The spec reverses a rule it adopted one version earlier. Reading This
  Document, the Service Description section and the Spaces Repositories section
  change from "must not assume peers" to "are peers under one base", and the
  reserved-segment list grows by three names. The changelog says plainly that
  this is a reversal.
- A second breaking was-client release follows 0.100.0. wallet-core,
  wallet-request, freewallet, was-react, dcw and the teaching server's testing
  counterpart had not yet shipped their 0002 ports, so the churn is confined to
  was-client and the spec. Greenfield: no migration of stored pointers or rows.
- Consumers may rely on: `{base}service`, `{base}spaces/` and
  `{base}space/{id}/` for any server built from a base server URL; a Space
  handle whose URL is byte-identical to what the server advertised, whichever
  entry point built it; a did:webvh minted by wallet-core resolving to its log
  and to its server's base with no stored value; `space(id)` being synchronous.
- A server loses the freedom to serve its Spaces from a different origin or path
  than its service description. No deployment has used it. A server that needs
  it can still hand out Space URLs through grants and DIDs, which `spaceAt`
  honours without reference to the base server URL.
- The `url` and `spaces` members of the service description become a consistency
  check rather than the source of the layout. They stay, so a description copied
  from a cache or a DID document can still be refetched and a misconfigured
  mount is caught early.
- The `Link: rel="service"` header stays required on every response, because the
  fixed-Space entry point and any client handed a bare Space URL depend on it.
- Root-mounted single-Space servers may not use `service`, `spaces` or `space`
  as collection ids.

## Revisit Criteria

1. A PWS deployment needs its Spaces on a different origin or path from its
   service description. Then the layout in rule 1 becomes one profile and a
   declared-layout profile (the URL template 0002 anticipated) is added beside
   it, as a new member of the service description, not as a change to the fixed
   layout.
2. A consumer needs a Space handle from a Space id on a server it knows only by
   a bare Space URL. That is the fixed-Space mode, which has no ids by
   construction; a server that grows ids must adopt a base server URL.
3. did:webvh changes how path segments are encoded in the method-specific id.
   The inverse in wallet-core follows the method; the base-server-URL derivation
   in rule 6 follows the inverse.
