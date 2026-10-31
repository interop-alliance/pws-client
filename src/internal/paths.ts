/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * URL builders beneath a Space. The layer above (the spec's Server Layout
 * and the canonical form of a Space URL) lives in `layout.ts`; here every
 * URL derives from the Space URL, which is either built there or handed out
 * by the server (the `Location` of the create response, a listing item, a
 * linkset, the caller's stored pointer) and used as given.
 *
 * The convention: a trailing slash marks a container in canonical form (the
 * Space URL itself, `{spaceUrl}{collectionId}/`, and a chunked Resource's
 * `chunks/` container), everything else has none, and no two URLs differ only
 * by a trailing slash. Path segments are percent-encoded so ids never break
 * out of their slot.
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
 * `PwsClient.fromCapability` does; refusing the bare form there would reject
 * valid capabilities over a form this client does not control.
 *
 * The zcap `invocationTarget` is derived from the request URL, so these
 * trailing-slash rules must match the server's per-operation `allowedTarget`
 * exactly or signature verification fails.
 */
import { ValidationError } from '../errors.js'
import {
  canonicalSpaceUrl,
  encode,
  isOriginRoot,
  parseContainerUrl
} from './layout.js'
import {
  assertNotReserved,
  isReservedCollectionId,
  isReservedResourceId
} from './reserved.js'

/**
 * Encodes a collection-id slot, additionally rejecting an id from the Reserved
 * Path Segment Registry: `collectionUrl` of `policy` is byte-identical to the
 * space policy URL, so a reserved id would silently mis-target a space-level
 * endpoint. Guarding in the builders covers every URL-forming entry point
 * (handle constructors guard too, for the earlier failure).
 *
 * @param options {object}
 * @param options.collectionId {string}
 * @param options.originRoot {boolean}   whether the Space is served from an
 *   origin root, where the server-level endpoint segments are reserved too
 * @returns {string}
 */
function encodeCollectionId({
  collectionId,
  originRoot
}: {
  collectionId: string
  originRoot: boolean
}): string {
  assertNotReserved({ id: collectionId, kind: 'collection', originRoot })
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
 * and `POST` registers one. Both take the controller's capability or a
 * delegated one whose chain roots in the Space's root capability. A grant on
 * the route names this bare URL as its `invocationTarget`, with no trailing
 * slash: the server matches it exactly, and the registration and status
 * URLs beneath it are reached through that one target.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function spaceReplicasUrl({ spaceUrl }: { spaceUrl: string }): string {
  return `${canonicalSpaceUrl(spaceUrl)}replicas`
}

/**
 * `{spaceUrl}replicas/{replicaId}` -- one replica registration (read,
 * replace and delete by id).
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
  const canonical = canonicalSpaceUrl(spaceUrl)
  // At an origin root the Collection id is the first path segment, where a
  // server with a base server URL places its three server-level endpoints,
  // so the spec reserves those segments there (and only there).
  const encodedId = encodeCollectionId({
    collectionId,
    originRoot: isOriginRoot(canonical)
  })
  return `${canonical}${encodedId}`
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
 * segment, so it needs no percent-encoding). Any other value throws a
 * `ValidationError`, since it would otherwise reach the path unencoded.
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
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0) {
    throw new ValidationError(
      `Chunk index must be a non-negative integer, got "${String(chunkIndex)}".`
    )
  }
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
 * grammar is owned in one place: `PwsClient.fromCapability` reads a
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
  if (
    isReservedCollectionId(segments[0] as string, {
      originRoot: base.pathname === '/'
    })
  ) {
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
