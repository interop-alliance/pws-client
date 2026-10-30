/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * URL builders for the two layers the spec fixes, encoding the trailing-slash
 * canonicalization once. Above a Space, the spec's Server Layout places the
 * three server-level endpoints under one base server URL:
 * `{base}service`, `{base}spaces/` and `{base}space/{space_id}/`
 * (`serviceDescriptionUrl`, `spacesRepositoryUrl`, `spaceUrlById`, with
 * `baseServerUrlOf` as their inverse). Beneath a Space, every URL derives from
 * the Space URL, which is either built that way or handed out by the server
 * (the `Location` of the create response, a listing item, a linkset, the
 * caller's stored pointer) and used as given. A single fixed Space has no
 * base server URL and may sit at an origin root, so a Space URL need not have
 * a path.
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
 * A container URL in canonical form: an absolute `http(s)` URL with no query
 * or fragment, serialized by `URL` (lower-case host, default port dropped),
 * ending in exactly one slash. A missing trailing slash is added, since the
 * bare form names the same container; a run of trailing slashes is collapsed
 * to one. An empty path segment is refused. The origin root (`https://h/`) is
 * a valid container.
 *
 * @param options {object}
 * @param options.url {string}
 * @param options.what {string}   what the URL was meant to name, for the error
 * @returns {string}
 * @throws {ValidationError}
 */
function canonicalContainer({
  url,
  what
}: {
  url: string
  what: string
}): string {
  const parsed = parseContainerUrl(url)
  if (parsed === null) {
    throw new ValidationError(
      `"${url}" is not a ${what}: an absolute http(s) URL with no query or ` +
        'fragment is required.'
    )
  }
  const pathname = parsed.pathname.replace(/\/+$/, '')
  if (pathname.split('/').slice(1).includes('')) {
    throw new ValidationError(
      `"${url}" is not a ${what}: its path has an empty segment.`
    )
  }
  return `${parsed.origin}${pathname}/`
}

/**
 * Whether a canonical container URL is an origin root (`https://h/`).
 *
 * @param canonical {string}
 * @returns {boolean}
 */
export function isOriginRoot(canonical: string): boolean {
  // Canonical form is `{origin}{path}/`, so the URL is a root when the first
  // slash after the scheme's `//` is its last character.
  const pathStart = canonical.indexOf('/', canonical.indexOf('//') + 2)
  return pathStart === canonical.length - 1
}

/**
 * The base server URL in canonical form: the URL under which a server lays
 * out `service`, `spaces/` and `space/{space_id}/`. An absolute `http(s)` URL
 * with no query or fragment; a missing trailing slash is supplied rather than
 * refused, since `https://h/pws` and `https://h/pws/` can only mean the same
 * mount.
 *
 * @param baseServerUrl {string}
 * @returns {string}
 * @throws {ValidationError}   when the value is not an absolute `http(s)` URL,
 *   or carries a query or fragment
 */
export function canonicalBaseServerUrl(baseServerUrl: string): string {
  return canonicalContainer({ url: baseServerUrl, what: 'base server URL' })
}

/**
 * `{base}service` -- the service description of the server at
 * `baseServerUrl`.
 *
 * @param options {object}
 * @param options.baseServerUrl {string}
 * @returns {string}
 */
export function serviceDescriptionUrl({
  baseServerUrl
}: {
  baseServerUrl: string
}): string {
  return `${canonicalBaseServerUrl(baseServerUrl)}service`
}

/**
 * `{base}spaces/` -- the Spaces Repository of the server at `baseServerUrl`,
 * in canonical container form. The server may not implement one; its service
 * description says.
 *
 * @param options {object}
 * @param options.baseServerUrl {string}
 * @returns {string}
 */
export function spacesRepositoryUrl({
  baseServerUrl
}: {
  baseServerUrl: string
}): string {
  return `${canonicalBaseServerUrl(baseServerUrl)}spaces/`
}

/**
 * `{base}space/{space_id}/` -- the Space with id `spaceId` on the server at
 * `baseServerUrl`, in canonical form. The one place a Space URL is built
 * rather than received; the spec's Server Layout fixes this shape.
 *
 * @param options {object}
 * @param options.baseServerUrl {string}
 * @param options.spaceId {string}
 * @returns {string}
 * @throws {ValidationError}   when `spaceId` is empty or a dot segment
 */
export function spaceUrlById({
  baseServerUrl,
  spaceId
}: {
  baseServerUrl: string
  spaceId: string
}): string {
  return `${canonicalBaseServerUrl(baseServerUrl)}space/${encode(spaceId)}/`
}

/**
 * The base server URL a server-level URL sits under: the inverse of
 * {@link serviceDescriptionUrl}, {@link spacesRepositoryUrl} and
 * {@link spaceUrlById}. Accepts the service description URL (`{base}service`),
 * the Spaces Repository URL (`{base}spaces/`, slash optional) or a Space URL
 * (`{base}space/{space_id}/`, slash optional) and strips exactly the segments
 * the layout adds. Anything else is refused, including a Collection or
 * Resource URL, whose depth cannot be told from the string alone, and the
 * URL of a single fixed Space, which has no base server URL.
 *
 * @param url {string}
 * @returns {string}
 * @throws {ValidationError}   when `url` is not an absolute `http(s)` URL
 *   without query or fragment in one of the three forms
 */
export function baseServerUrlOf(url: string): string {
  const parsed = parseContainerUrl(url)
  const segments = parsed?.pathname.split('/').filter(Boolean) ?? []
  const last = segments.at(-1)
  // The Space form is tested first: a Space whose id is itself `spaces` or
  // `service` still sits under `space/`, and the other two forms have no
  // `space` segment before their last one.
  const isSpace = segments.at(-2) === 'space'
  const isServerLevel =
    isSpace ||
    last === 'spaces' ||
    (last === 'service' && !parsed?.pathname.endsWith('/'))
  if (parsed === null || !isServerLevel) {
    throw new ValidationError(
      `"${url}" is not a server-level PWS URL: expected the service ` +
        'description (`{base}service`), the Spaces Repository ' +
        '(`{base}spaces/`) or a Space (`{base}space/{space_id}/`).'
    )
  }
  const base = segments.slice(0, isSpace ? -2 : -1)
  return `${parsed.origin}/${base.map(segment => `${segment}/`).join('')}`
}

/**
 * Splits an absolute Collection URL into the Space URL it sits under and the
 * Collection id: the parent container and the last segment, percent-decoded.
 * A Collection URL is always the Space URL plus one segment, so no layout
 * knowledge is needed. The bare form (no trailing slash) is accepted, as for
 * any container URL received from outside.
 *
 * @param collectionUrl {string}
 * @returns {{ spaceUrl: string; collectionId: string }}
 * @throws {ValidationError}   when `collectionUrl` is not an absolute `http(s)`
 *   URL without query or fragment, has no path segment, or its last segment
 *   is a malformed percent escape
 */
export function splitCollectionUrl(collectionUrl: string): {
  spaceUrl: string
  collectionId: string
} {
  const canonical = canonicalContainer({
    url: collectionUrl,
    what: 'Collection URL'
  })
  if (isOriginRoot(canonical)) {
    throw new ValidationError(
      `"${collectionUrl}" is not a Collection URL: a Collection has at least ` +
        'one path segment beneath its origin.'
    )
  }
  const parsed = new URL(canonical)
  const segments = parsed.pathname.split('/').filter(Boolean)
  const encodedId = segments.pop() as string
  let collectionId: string
  try {
    collectionId = decodeURIComponent(encodedId)
  } catch (err) {
    throw new ValidationError(
      `"${collectionUrl}" is not a Collection URL: its last segment is not ` +
        'a well-formed percent-encoding.',
      { cause: err }
    )
  }
  const parent = segments.length === 0 ? '' : `${segments.join('/')}/`
  return { spaceUrl: `${parsed.origin}/${parent}`, collectionId }
}

/**
 * The Space URL in canonical form (see `canonicalContainer`). A server names
 * a Space in this form (the `Location` of the create response, a listing
 * item's `url`), and every URL beneath the Space, and every zcap
 * `invocationTarget`, is derived from it, so a caller's own serialization of
 * the same Space must reduce to the same string. An origin root is a valid
 * Space URL: a single fixed Space (one with no Space id and no base server
 * URL) may be served there.
 *
 * @param spaceUrl {string}   a Space URL, as the server named it or as the
 *   caller stored it
 * @returns {string}
 * @throws {ValidationError}   when `spaceUrl` is not an absolute `http(s)`
 *   URL, carries a query or fragment, or has an empty path segment
 */
export function canonicalSpaceUrl(spaceUrl: string): string {
  const canonical = canonicalContainer({ url: spaceUrl, what: 'Space URL' })
  // The last segment is the Space id, percent-encoded; a malformed escape
  // (`%ff`) is refused here so every handle beneath the Space (not only the
  // Space handle, which decodes the id) rejects an unparseable Space URL.
  spaceIdOfCanonicalUrl(canonical)
  return canonical
}

/**
 * The Space's id as its URL names it: the last path segment of the Space
 * URL, percent-decoded. The spec's hierarchy and its did:webvh profile both
 * place the id there (`.../space/{space_id}/`), and it is the value the Space
 * Metadata object's `id` carries. A single fixed Space at an origin root has
 * no id, so that URL is refused here.
 *
 * @param spaceUrl {string}   a Space URL
 * @returns {string}
 * @throws {ValidationError}   when `spaceUrl` is not a Space URL (see
 *   {@link canonicalSpaceUrl}), is an origin root, or its last segment is a
 *   malformed percent escape
 */
export function spaceIdOfUrl(spaceUrl: string): string {
  const id = spaceIdOfCanonicalUrl(canonicalSpaceUrl(spaceUrl))
  if (id === undefined) {
    throw new ValidationError(
      `"${spaceUrl}" names no Space id: it is an origin root, which only a ` +
        'single fixed Space (one without an id) is served from.'
    )
  }
  return id
}

/**
 * {@link spaceIdOfUrl} for a Space URL already in canonical form (a handle's
 * `url`, the result of {@link canonicalSpaceUrl}), sparing the second parse.
 * Returns `undefined` for an origin root, which has no id segment.
 *
 * @param canonical {string}   a canonical Space URL
 * @returns {string | undefined}
 * @throws {ValidationError}   when the last segment is a malformed percent
 *   escape
 */
export function spaceIdOfCanonicalUrl(canonical: string): string | undefined {
  if (isOriginRoot(canonical)) {
    return undefined
  }
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
