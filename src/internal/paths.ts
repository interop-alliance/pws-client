/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * URL builders for the hierarchy beneath a Space, encoding the trailing-slash
 * canonicalization once. Every URL this client requests is derived from a
 * Space URL the server handed out (the `Location` of the create response, a
 * listing item, a linkset, or the caller's stored pointer) and from nothing
 * above it: the spec places no Space beside the Spaces Repository, so no
 * builder here forms a Space URL, and none takes a server root. The Spaces
 * Repository URL is the `spaces` member of the service description.
 *
 * The convention: a trailing slash marks a container in canonical form (the
 * Space URL itself, and `{spaceUrl}{collectionId}/`), everything else has
 * none, and no two URLs differ only by a trailing slash. Path segments are
 * percent-encoded so ids never break out of their slot.
 *
 * A container's own description is not at its URL: it lives at the reserved
 * `meta` segment (`spaceMetaUrl`, `collectionMetaUrl`), beside the
 * Resource-level `resourceMetaUrl`. The bare (slash-less) form of a container
 * URL only 308-redirects, and a signed invocation covers the target it was
 * signed for, so no builder here emits the bare form -- a redirect would have
 * to be signed again.
 *
 * The parser is deliberately laxer than the builders. `parseSpaceTarget`
 * accepts the bare container form too, because the targets it classifies are
 * not this client's own URLs: they are the `invocationTarget` strings of
 * delegated capabilities a third party minted, and those name containers in
 * either form. Reading one as the Collection or Resource it addresses is what
 * `WasClient.fromCapability` does; refusing the bare form there would reject
 * valid capabilities over a form this client does not control.
 *
 * The zcap `invocationTarget` is derived from the request URL, so these
 * trailing-slash rules must match the server's per-operation `allowedTarget`
 * exactly or signature verification fails.
 */
import { ValidationError } from '../errors.js'
import {
  assertNotReserved,
  isReservedCollectionId,
  isReservedResourceId
} from './reserved.js'

/**
 * Rejects an id that would escape its path slot even after percent-encoding:
 * `encodeURIComponent` leaves `.` and `..` intact, and WHATWG URL resolution
 * collapses dot segments -- so `resource('.').delete()` would target the
 * collection items endpoint and `'..'` the parent space. An empty id likewise
 * collapses into the parent's trailing-slash endpoint. One guard here covers
 * every builder.
 *
 * @param segment {string}   the proposed id
 * @returns {void}
 */
function assertValidId(segment: string): void {
  if (segment === '' || segment === '.' || segment === '..') {
    throw new ValidationError(
      `Invalid id ${JSON.stringify(segment)}: an empty or dot-segment id ` +
        'would resolve to a different endpoint than its own.'
    )
  }
}

function encode(segment: string): string {
  assertValidId(segment)
  return encodeURIComponent(segment)
}

/**
 * Encodes a collection-id slot, additionally rejecting an id from the Reserved
 * Path Segment Registry: `collectionUrl` of `policy` is byte-identical to the
 * space policy URL, so a reserved id would silently mis-target a space-level
 * endpoint. Guarding in the builders covers every URL-forming entry point
 * (handle constructors guard too, for the earlier failure).
 *
 * @param collectionId {string}
 * @returns {string}
 */
function encodeCollectionId(collectionId: string): string {
  assertNotReserved({ id: collectionId, kind: 'collection' })
  return encode(collectionId)
}

/**
 * Encodes a resource-id slot, additionally rejecting an id from the Reserved
 * Path Segment Registry: `resourceUrl` of `policy` is byte-identical to the
 * collection policy URL, so a reserved id would silently mis-target a
 * collection-level endpoint.
 *
 * @param resourceId {string}
 * @returns {string}
 */
function encodeResourceId(resourceId: string): string {
  assertNotReserved({ id: resourceId, kind: 'resource' })
  return encode(resourceId)
}

/**
 * Parses an absolute `http(s)` URL, or returns `null`. The one rule for which
 * URLs may name a server, a Spaces Repository, or a container here; the
 * callers that need more (no query, a path) narrow it.
 *
 * @param url {string}
 * @returns {URL | null}
 */
export function parseAbsoluteHttpUrl(url: string): URL | null {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return null
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return null
  }
  return parsed
}

/**
 * {@link parseAbsoluteHttpUrl} narrowed to a URL with no query or fragment:
 * the rule for which URLs may name a container.
 *
 * @param url {string}
 * @returns {URL | null}
 */
function parseContainerUrl(url: string): URL | null {
  const parsed = parseAbsoluteHttpUrl(url)
  if (parsed === null || parsed.search !== '' || parsed.hash !== '') {
    return null
  }
  return parsed
}

/**
 * The Space URL in canonical form: an absolute `http(s)` URL, serialized by
 * `URL` (lower-case host, default port dropped), ending in exactly one
 * slash. A server names a Space in this form (the `Location` of the create
 * response, a listing item's `url`), and every URL beneath the Space, and
 * every zcap `invocationTarget`, is derived from it, so a caller's own
 * serialization of the same Space must reduce to the same string. A missing
 * trailing slash is added, since the bare form names the same container; a
 * run of trailing slashes is collapsed to one.
 *
 * @param spaceUrl {string}   a Space URL, as the server named it or as the
 *   caller stored it
 * @returns {string}
 * @throws {ValidationError}   when `spaceUrl` is not an absolute `http(s)`
 *   URL, carries a query or fragment, or has no path segment (an origin is
 *   not a Space)
 */
export function canonicalSpaceUrl(spaceUrl: string): string {
  const parsed = parseContainerUrl(spaceUrl)
  if (parsed === null) {
    throw new ValidationError(
      `"${spaceUrl}" is not a Space URL: an absolute http(s) URL with no ` +
        'query or fragment is required.'
    )
  }
  const pathname = parsed.pathname.replace(/\/+$/, '')
  if (pathname === '' || pathname.split('/').slice(1).includes('')) {
    throw new ValidationError(
      `"${spaceUrl}" is not a Space URL: a Space has at least one path ` +
        'segment beneath its origin, with no empty segment.'
    )
  }
  return `${parsed.origin}${pathname}/`
}

/**
 * The Space's id as its URL names it: the last path segment of the Space
 * URL, percent-decoded. The spec's hierarchy and its did:webvh profile both
 * place the id there (`.../space/{space_id}/`), and it is the value the Space
 * Metadata object's `id` carries.
 *
 * @param spaceUrl {string}   a Space URL
 * @returns {string}
 * @throws {ValidationError}   when `spaceUrl` is not a Space URL (see
 *   {@link canonicalSpaceUrl}) or its last segment is a malformed percent
 *   escape
 */
export function spaceIdOfUrl(spaceUrl: string): string {
  return spaceIdOfCanonicalUrl(canonicalSpaceUrl(spaceUrl))
}

/**
 * {@link spaceIdOfUrl} for a Space URL already in canonical form (a handle's
 * `url`, the result of {@link canonicalSpaceUrl}), sparing the second parse.
 *
 * @param canonical {string}   a canonical Space URL
 * @returns {string}
 * @throws {ValidationError}   when the last segment is a malformed percent
 *   escape
 */
export function spaceIdOfCanonicalUrl(canonical: string): string {
  const segment = canonical.split('/').filter(Boolean).pop() as string
  try {
    return decodeURIComponent(segment)
  } catch (err) {
    throw new ValidationError(
      `"${canonical}" is not a Space URL: its last segment is not a ` +
        'well-formed percent-encoded id.',
      { cause: err }
    )
  }
}

/**
 * `{spaceUrl}meta` -- the Space Metadata object: the Space's description
 * (`name`, `controller`, `type`), read with `GET` and replaced with `PUT`.
 * The Space container itself (the canonical Space URL) is the target a Space
 * root capability names, the URL whose `GET` lists the Space's Collections,
 * whose `POST` creates one, and whose `DELETE` removes the Space; it has no
 * builder, since the caller holds it.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function spaceMetaUrl({ spaceUrl }: { spaceUrl: string }): string {
  return `${canonicalSpaceUrl(spaceUrl)}meta`
}

/**
 * `{spaceUrl}export` -- export a space as a tar archive.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function spaceExportUrl({ spaceUrl }: { spaceUrl: string }): string {
  return `${canonicalSpaceUrl(spaceUrl)}export`
}

/**
 * `{spaceUrl}import` -- import a tar archive into a space.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function spaceImportUrl({ spaceUrl }: { spaceUrl: string }): string {
  return `${canonicalSpaceUrl(spaceUrl)}import`
}

/**
 * `{spaceUrl}backends` -- the backends available within a space (list, and
 * register a new `external` backend).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function spaceBackendsUrl({ spaceUrl }: { spaceUrl: string }): string {
  return `${canonicalSpaceUrl(spaceUrl)}backends`
}

/**
 * `{spaceUrl}backends/{backendId}` -- a single registered `external` backend
 * (replace / deregister by id).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.backendId {string}
 * @returns {string}
 */
export function registeredBackendUrl({
  spaceUrl,
  backendId
}: {
  spaceUrl: string
  backendId: string
}): string {
  return `${spaceBackendsUrl({ spaceUrl })}/${encode(backendId)}`
}

/**
 * `{spaceUrl}quotas` -- the space-level storage quota report.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function spaceQuotasUrl({ spaceUrl }: { spaceUrl: string }): string {
  return `${canonicalSpaceUrl(spaceUrl)}quotas`
}

/**
 * `{spaceUrl}policy` -- the space-level access-control policy resource.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function spacePolicyUrl({ spaceUrl }: { spaceUrl: string }): string {
  return `${canonicalSpaceUrl(spaceUrl)}policy`
}

/**
 * `{spaceUrl}linkset` -- the space-level linkset (policy discovery).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function spaceLinksetUrl({ spaceUrl }: { spaceUrl: string }): string {
  return `${canonicalSpaceUrl(spaceUrl)}linkset`
}

/**
 * `{spaceUrl}replicas` -- the Space's replica registrations: `GET` lists them
 * and `POST` registers one. Controller-only, both forms.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function spaceReplicasUrl({ spaceUrl }: { spaceUrl: string }): string {
  return `${canonicalSpaceUrl(spaceUrl)}replicas`
}

/**
 * `{spaceUrl}replicas/{replicaId}` -- one replica registration (read and
 * delete by id).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.replicaId {string}
 * @returns {string}
 */
export function replicaRegistrationUrl({
  spaceUrl,
  replicaId
}: {
  spaceUrl: string
  replicaId: string
}): string {
  return `${spaceReplicasUrl({ spaceUrl })}/${encode(replicaId)}`
}

/**
 * `{spaceUrl}replicas/{replicaId}/status` -- the pull loop's runtime state
 * for one registration.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.replicaId {string}
 * @returns {string}
 */
export function replicaStatusUrl({
  spaceUrl,
  replicaId
}: {
  spaceUrl: string
  replicaId: string
}): string {
  return `${replicaRegistrationUrl({ spaceUrl, replicaId })}/status`
}

/**
 * `{spaceUrl}zcaps/revocations/{capabilityId}` -- submit a revocation of a
 * Space-rooted capability. The capability's `id` (typically a `urn:uuid:`) is
 * percent-encoded into the single final segment. `zcaps` is in the Reserved
 * Path Segment Registry, so no Collection can take that slot.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.capabilityId {string}
 * @returns {string}
 */
export function spaceRevocationUrl({
  spaceUrl,
  capabilityId
}: {
  spaceUrl: string
  capabilityId: string
}): string {
  return `${canonicalSpaceUrl(spaceUrl)}zcaps/revocations/${encode(capabilityId)}`
}

/**
 * `{spaceUrl}{collectionId}` -- the slash-less prefix the collection-level
 * sub-endpoints and the Resource ids hang off. Module-private: the bare form
 * is not a URL this client ever requests (the server only 308-redirects it),
 * so it is a prefix here and never a builder's return value.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
function collectionPrefix({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return `${canonicalSpaceUrl(spaceUrl)}${encodeCollectionId(collectionId)}`
}

/**
 * `{spaceUrl}{collectionId}/` -- the Collection container in canonical form:
 * the target a "share this collection" capability names, the URL whose `GET`
 * lists its Resources, whose `POST` adds one, and whose `DELETE` removes the
 * Collection.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
export function collectionUrl({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return `${collectionPrefix({ spaceUrl, collectionId })}/`
}

/**
 * `{spaceUrl}{collectionId}/policy` -- the collection-level access-control
 * policy resource.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
export function collectionPolicyUrl({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return `${collectionPrefix({ spaceUrl, collectionId })}/policy`
}

/**
 * `{spaceUrl}{collectionId}/linkset` -- the collection-level linkset (policy
 * discovery).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
export function collectionLinksetUrl({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return `${collectionPrefix({ spaceUrl, collectionId })}/linkset`
}

/**
 * `{spaceUrl}{collectionId}/backend` -- the "Collection Backend Selected"
 * descriptor (the backend this collection is stored on).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
export function collectionBackendUrl({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return `${collectionPrefix({ spaceUrl, collectionId })}/backend`
}

/**
 * `{spaceUrl}{collectionId}/quota` -- the per-collection storage quota report
 * (spec "Quotas").
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
export function collectionQuotaUrl({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return `${collectionPrefix({ spaceUrl, collectionId })}/quota`
}

/**
 * `{spaceUrl}{collectionId}/meta` -- the Collection Metadata object: the
 * Collection's configuration (`name`, `backend`, `encryption`, `generator`)
 * together with the server-managed timestamps / `createdBy` and the
 * user-writable `custom` and `epoch`, as one object under one validator.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
export function collectionMetaUrl({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return `${collectionPrefix({ spaceUrl, collectionId })}/meta`
}

/**
 * `{spaceUrl}{collectionId}/meta/log` -- the Collection's governing history
 * log sub-resource (JSON Lines). Not a Resource of the Collection: absent from
 * listings and the `changes` feed, and versioned by its own ETag.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
export function collectionLogUrl({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return `${collectionMetaUrl({ spaceUrl, collectionId })}/log`
}

/**
 * `{spaceUrl}{collectionId}/query` -- the collection-level query endpoint,
 * whose body's `profile` selects the query (e.g. `changes`, `blinded-index`).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
export function collectionQueryUrl({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return `${collectionPrefix({ spaceUrl, collectionId })}/query`
}

/**
 * `{spaceUrl}{collectionId}/{resourceId}` -- get / put / delete a resource
 * (no trailing slash).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @returns {string}
 */
export function resourceUrl({
  spaceUrl,
  collectionId,
  resourceId
}: {
  spaceUrl: string
  collectionId: string
  resourceId: string
}): string {
  return `${collectionPrefix({ spaceUrl, collectionId })}/${encodeResourceId(resourceId)}`
}

/**
 * `{spaceUrl}{collectionId}/{resourceId}/meta` -- the resource metadata
 * object (server-managed properties plus the user-writable `custom` object).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @returns {string}
 */
export function resourceMetaUrl({
  spaceUrl,
  collectionId,
  resourceId
}: {
  spaceUrl: string
  collectionId: string
  resourceId: string
}): string {
  return `${resourceUrl({ spaceUrl, collectionId, resourceId })}/meta`
}

/**
 * `{spaceUrl}{collectionId}/{resourceId}/policy` -- the resource-level
 * access-control policy resource.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @returns {string}
 */
export function resourcePolicyUrl({
  spaceUrl,
  collectionId,
  resourceId
}: {
  spaceUrl: string
  collectionId: string
  resourceId: string
}): string {
  return `${resourceUrl({ spaceUrl, collectionId, resourceId })}/policy`
}

/**
 * `{spaceUrl}{collectionId}/{resourceId}/chunks/{chunkIndex}` -- a single
 * stored chunk of a chunked Resource. Member form, no trailing slash: get /
 * put / delete one chunk by its ordinal index. The `chunkIndex` is a
 * non-negative integer, emitted verbatim (it is never a reserved or dot
 * segment, so it needs no percent-encoding).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @param options.chunkIndex {number}
 * @returns {string}
 */
export function resourceChunkUrl({
  spaceUrl,
  collectionId,
  resourceId,
  chunkIndex
}: {
  spaceUrl: string
  collectionId: string
  resourceId: string
  chunkIndex: number
}): string {
  return `${resourceUrl({ spaceUrl, collectionId, resourceId })}/chunks/${chunkIndex}`
}

/**
 * `{spaceUrl}{collectionId}/{resourceId}/chunks/` -- the chunk container of a
 * chunked Resource: its stored chunks, listed. Container form, trailing slash
 * (the member form, {@link resourceChunkUrl}, has none).
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @returns {string}
 */
export function resourceChunksUrl({
  spaceUrl,
  collectionId,
  resourceId
}: {
  spaceUrl: string
  collectionId: string
  resourceId: string
}): string {
  return `${resourceUrl({ spaceUrl, collectionId, resourceId })}/chunks/`
}

/**
 * The canonical (trailing-slash) form of a container URL received from
 * outside and requested as given: the Spaces Repository URL a service
 * description advertises, a public Collection link. The bare form only
 * 308-redirects, and a signed invocation does not survive the redirect, so
 * the slash is added here before the URL is ever requested. This module owns
 * the trailing-slash rules; callers normalize here rather than re-encoding
 * the rule.
 *
 * @param url {string}   an absolute container URL, in either form
 * @returns {string}
 */
export function canonicalContainerUrl(url: string): string {
  // The slash marks the end of the path, so it goes before any query or
  // fragment; the rest of the URL is kept as given.
  const pathEnd = url.search(/[?#]/)
  const path = pathEnd === -1 ? url : url.slice(0, pathEnd)
  if (path.endsWith('/')) {
    return url
  }
  return pathEnd === -1 ? `${url}/` : `${path}/${url.slice(pathEnd)}`
}

/**
 * The classification of a URL beneath a Space by the depth it addresses. The
 * three containment kinds map onto navigational handles; `sub-resource`
 * covers every reserved sub-endpoint the builders above produce (`policy`,
 * `{c}/backend`, `{c}/{r}/meta`, ...), which has no handle of its own.
 */
export type ParsedSpacePath =
  | { kind: 'space' }
  | { kind: 'collection'; collectionId: string }
  | { kind: 'resource'; collectionId: string; resourceId: string }
  | { kind: 'sub-resource'; segments: string[] }

/**
 * Classifies an absolute `target` URL by where it sits beneath `spaceUrl`:
 * the Space itself, one of its Collections, a Resource, or a reserved
 * sub-endpoint. The inverse of the builders above, kept next to them so the
 * grammar is owned in one place: `WasClient.fromCapability` reads a
 * capability's `invocationTarget` through it, and the builders stay in
 * lockstep.
 *
 * Both URLs are compared in parsed form, so a target serialized by another
 * party (an upper-case host, a default port) still matches. Segments are
 * percent-decoded (the builders re-encode them). Empty segments are dropped,
 * so a container addressed in either form classifies the same: the bare and
 * the trailing-slash form of a Collection are both the Collection. That is
 * deliberate: the builders emit only the canonical form, but the targets
 * parsed here come from capabilities minted elsewhere, and a client that
 * reads only one form would refuse valid ones.
 *
 * Returns `null` when `target` is not beneath `spaceUrl` (another origin, or
 * another path), carries a query or fragment, or either URL is malformed.
 * The caller chooses whether that is an error.
 *
 * @param options {object}
 * @param options.spaceUrl {string}   the Space URL
 * @param options.target {string}     an absolute URL expected beneath it
 * @returns {ParsedSpacePath | null}
 */
export function parseSpaceTarget({
  spaceUrl,
  target
}: {
  spaceUrl: string
  target: string
}): ParsedSpacePath | null {
  let base: URL
  try {
    base = new URL(canonicalSpaceUrl(spaceUrl))
  } catch {
    return null
  }
  const url = parseContainerUrl(target)
  if (url === null || url.origin !== base.origin) {
    return null
  }
  // The bare form of the Space itself (`.../space/s`, no slash) names the
  // Space too, so the prefix check reads the path without its final slash.
  const basePath = base.pathname.slice(0, -1)
  if (url.pathname !== basePath && !url.pathname.startsWith(`${basePath}/`)) {
    return null
  }
  let segments: string[]
  try {
    segments = url.pathname
      .slice(basePath.length)
      .split('/')
      .filter(Boolean)
      .map(decodeURIComponent)
  } catch {
    // A malformed percent-escape (e.g. `%ff`) makes `decodeURIComponent` throw
    // a `URIError`: the path is not a well-formed target, so classify it as
    // unparseable (the caller converts `null` to its own typed error).
    return null
  }
  if (segments.length === 0) {
    return { kind: 'space' }
  }
  // A reserved segment directly under the space (`policy`, `backends`,
  // `export`, ...) addresses a space-level sub-endpoint, as does anything
  // nested beneath one (`backends/{backendId}`).
  if (isReservedCollectionId(segments[0] as string)) {
    return { kind: 'sub-resource', segments }
  }
  if (segments.length === 1) {
    return { kind: 'collection', collectionId: segments[0] as string }
  }
  // A reserved segment under the collection (`policy`, `backend`, `quota`,
  // ...) addresses a collection-level sub-endpoint.
  if (isReservedResourceId(segments[1] as string)) {
    return { kind: 'sub-resource', segments }
  }
  if (segments.length === 2) {
    return {
      kind: 'resource',
      collectionId: segments[0] as string,
      resourceId: segments[1] as string
    }
  }
  // Anything deeper (`{c}/{r}/meta`, `{c}/{r}/policy`, chunk sub-segments,
  // ...) is a resource-level sub-endpoint.
  return { kind: 'sub-resource', segments }
}
