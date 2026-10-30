/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The dependency-free part of the URL grammar: the spec's Server Layout
 * above a Space and the canonical form of a Space URL. A server lays out its
 * three server-level endpoints under one base server URL, `{base}service`,
 * `{base}spaces/` and `{base}space/{space_id}/` (`serviceDescriptionUrl`,
 * `spacesRepositoryUrl`, `spaceUrlById`, with `baseServerUrlOf` as their
 * inverse), and `canonicalBaseServerUrl` is the one rule for what that base
 * is. Beneath it, `canonicalSpaceUrl` is the one rule for what a Space URL is
 * (an origin root is a valid one, since a single fixed Space may be served
 * there), `spaceIdOfUrl` reads the id off its last segment, and
 * `splitCollectionUrl` takes a Collection URL apart into the Space URL and
 * the id, which needs no layout knowledge since a Collection is always one
 * segment beneath its Space.
 *
 * The convention, shared with `paths.ts`: a trailing slash marks a container
 * in canonical form, everything else has none, and no two URLs differ only by
 * a trailing slash. `canonicalContainer` encodes it once, for the base server
 * URL and the Space URL alike; `paths.ts` builds every URL beneath a Space on
 * top of `canonicalSpaceUrl`.
 *
 * Nothing here reaches past the platform `URL` and the `ValidationError`
 * class: `paths.ts` needs the Reserved Path Segment Registry from
 * `@interop/storage-core` for its id guards, and this module is what the
 * `./paths/layout` entry exposes without it (the entry's header says why).
 */
import { ValidationError } from '../errors.js'

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

/**
 * Percent-encodes one id for its URL slot, after `assertValidId`. The one id
 * encoder for both grammar modules, so every builder refuses the same ids.
 *
 * @param segment {string}
 * @returns {string}
 */
export function encode(segment: string): string {
  assertValidId(segment)
  return encodeURIComponent(segment)
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
 * Whether a parsed URL carries userinfo (a username or password). The one
 * rule for it, shared by the container URL canonicalizer and the listing
 * pager's `next` link check.
 *
 * @param url {URL}
 * @returns {boolean}
 */
export function hasUserinfo(url: URL): boolean {
  return url.username !== '' || url.password !== ''
}

/**
 * {@link parseAbsoluteHttpUrl} narrowed to a URL with no query, no fragment
 * (a bare `?` or `#` counts), and no userinfo: the rule for which URLs may
 * name a container.
 *
 * @param url {string}
 * @returns {URL | null}
 */
export function parseContainerUrl(url: string): URL | null {
  // The input is checked for the markers rather than `search` / `hash`,
  // which are both '' for a bare trailing `?` or `#`; those still mark a
  // query or fragment. Userinfo is not part of the origin and so would be
  // dropped from the canonical form; refuse it rather than rewrite the value.
  if (url.includes('?') || url.includes('#')) {
    return null
  }
  const parsed = parseAbsoluteHttpUrl(url)
  if (parsed === null || hasUserinfo(parsed)) {
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
      `"${url}" is not a ${what}: an absolute http(s) URL with no query, ` +
        'fragment, or userinfo is required.'
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
 * with no query, fragment, or userinfo; a missing trailing slash is supplied
 * rather than refused, since `https://h/pws` and `https://h/pws/` can only
 * mean the same mount.
 *
 * @param baseServerUrl {string}
 * @returns {string}
 * @throws {ValidationError}   when the value is not an absolute `http(s)` URL,
 *   carries a query, fragment, or userinfo, or has an empty path segment
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
 *   URL, carries a query, fragment, or userinfo, or has an empty path segment
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
