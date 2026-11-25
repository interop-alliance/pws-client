/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Service discovery: reads the server's service description without a
 * capability invocation and selects the PWS specification version and the
 * zCap authorization profile version this client speaks. A client built from
 * a base server URL reads the document directly at `{base}service`
 * (`readServiceDescription`). One opened on a single fixed
 * Space, which has no base, follows the `Link: <...>; rel="service"` header
 * the server's responses carry (`discoverService`), probing the Space URL
 * itself. The client speaks only v0.5, so a server whose responses carry no
 * `service` link (one that predates v0.5) is refused rather than spoken to in
 * the v0.4 layout.
 */
import {
  AUTHZ_PROFILE_SPEC_ID,
  CLIENT_ANNEX_SPEC_ID,
  ENCRYPTED_COLLECTIONS_SPEC_ID,
  PWS_SPEC_ID,
  REPLICATION_SPEC_ID,
  WALLET_PROFILE_SPEC_ID
} from '@interop/storage-core'
import type {
  AuthzProfileVersionEntry,
  PwsVersionEntry,
  ServiceDescription,
  ServiceDescriptionVersionEntry
} from '@interop/storage-core'
import { IncompatibleServerError } from '../errors.js'
import { mapError } from './mapError.js'
import { canonicalContainerUrl } from './paths.js'
import { parseAbsoluteHttpUrl } from './layout.js'
import { fetchMapped } from './request.js'
import type { ServiceInfo } from '../types.js'

/**
 * The PWS specification versions this client speaks, newest first. Selection
 * takes the first one the server lists.
 */
export const SUPPORTED_PWS_VERSIONS = ['0.5']

/**
 * The zCap authorization profile versions this client speaks, newest first.
 * The profile describes the credential the client constructs: an Ed25519
 * `did:key` capability invocation with the `Digest` header.
 */
export const SUPPORTED_AUTHZ_PROFILE_VERSIONS = ['0.1']

/**
 * The versions this client speaks of each companion specification, newest
 * first, keyed by the specification's identifier. A companion is optional. A
 * server that lists none of these versions is still spoken to, and
 * `hasFeature` answers `false` for that specification.
 */
export const SUPPORTED_COMPANION_VERSIONS: Record<string, string[]> = {
  [ENCRYPTED_COLLECTIONS_SPEC_ID]: ['0.1'],
  [REPLICATION_SPEC_ID]: ['0.1'],
  [CLIENT_ANNEX_SPEC_ID]: ['0.1'],
  [WALLET_PROFILE_SPEC_ID]: ['0.1']
}

/**
 * The link relation that names the service description.
 */
const SERVICE_RELATION = 'service'

/**
 * Splits a `Link` header value into its link-values: on commas outside a
 * `<...>` target and outside a quoted parameter value.
 *
 * @param header {string}
 * @returns {string[]}
 */
function splitLinkValues(header: string): string[] {
  const values: string[] = []
  let current = ''
  let inTarget = false
  let inQuotes = false
  for (let index = 0; index < header.length; index++) {
    const char = header[index] as string
    if (inQuotes) {
      current += char
      if (char === '\\' && index + 1 < header.length) {
        current += header[++index]
      } else if (char === '"') {
        inQuotes = false
      }
      continue
    }
    if (char === '<') {
      inTarget = true
    } else if (char === '>') {
      inTarget = false
    } else if (char === '"' && !inTarget) {
      inQuotes = true
    } else if (char === ',' && !inTarget) {
      values.push(current)
      current = ''
      continue
    }
    current += char
  }
  values.push(current)
  return values
}

/**
 * Reads the target of the first `service` link in a `Link` header (RFC 8288),
 * resolved against the URL of the response that carried it. Relation types
 * compare case-insensitively, a `rel` may list several space-separated types,
 * and only the first `rel` parameter of a link-value counts.
 *
 * @param options {object}
 * @param options.header {string | null}   the `Link` header value
 * @param options.baseUrl {string}   the URL the response came from
 * @returns {string | undefined}   the absolute service description URL
 */
export function serviceLinkTarget({
  header,
  baseUrl
}: {
  header: string | null
  baseUrl: string
}): string | undefined {
  if (header === null) {
    return undefined
  }
  for (const linkValue of splitLinkValues(header)) {
    const match = /^\s*<([^>]*)>(.*)$/s.exec(linkValue)
    if (match === null) {
      continue
    }
    const [, target, rest] = match as unknown as [string, string, string]
    const relParam = rest
      .split(';')
      .map(param =>
        /^\s*rel\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s;]*))/i.exec(param)
      )
      .find(paramMatch => paramMatch !== null)
    const relValue = relParam?.[1] ?? relParam?.[2] ?? ''
    const relations = relValue.toLowerCase().split(/\s+/)
    if (relations.includes(SERVICE_RELATION)) {
      try {
        return new URL(target, baseUrl).toString()
      } catch {
        continue
      }
    }
  }
  return undefined
}

/**
 * Whether a value is a JSON object (not `null`, not an array).
 *
 * @param value {unknown}
 * @returns {boolean}
 */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Lists the well-formed version entries a service description carries for
 * one specification. An entry without a string `version` is left out.
 *
 * @param options {object}
 * @param options.specs {Record<string, unknown>}   the `specs` member
 * @param options.spec {string}   the specification's identifier
 * @returns {ServiceDescriptionVersionEntry[]}
 */
function versionEntries({
  specs,
  spec
}: {
  specs: Record<string, unknown>
  spec: string
}): ServiceDescriptionVersionEntry[] {
  const candidates = specs[spec]
  return (Array.isArray(candidates) ? candidates : []).filter(
    (entry): entry is ServiceDescriptionVersionEntry =>
      isObject(entry) && typeof entry.version === 'string'
  )
}

/**
 * Picks the version entry of one specification from a service description:
 * the newest version in `supported` that the server lists under `spec`.
 *
 * @param options {object}
 * @param options.specs {Record<string, unknown>}   the `specs` member
 * @param options.spec {string}   the specification's identifier
 * @param options.supported {string[]}   the versions this client speaks,
 *   newest first
 * @returns {ServiceDescriptionVersionEntry | undefined}   `undefined` when
 *   the server lists no supported version
 */
function chooseEntry({
  specs,
  spec,
  supported
}: {
  specs: Record<string, unknown>
  spec: string
  supported: string[]
}): ServiceDescriptionVersionEntry | undefined {
  const entries = versionEntries({ specs, spec })
  let chosen: ServiceDescriptionVersionEntry | undefined
  for (const version of supported) {
    chosen = entries.find(entry => entry.version === version)
    if (chosen !== undefined) {
      break
    }
  }
  return chosen
}

/**
 * Whether a version entry's `features`, which the client acts on, is absent
 * or an array of strings.
 *
 * @param entry {ServiceDescriptionVersionEntry}
 * @returns {boolean}
 */
function hasWellFormedFeatures(entry: ServiceDescriptionVersionEntry): boolean {
  const { features } = entry
  return (
    features === undefined ||
    (Array.isArray(features) &&
      features.every(token => typeof token === 'string'))
  )
}

/**
 * Picks the version entry of a specification the client cannot work without
 * (see {@link chooseEntry}).
 *
 * @param options {object}
 * @param options.url {string}   the service description's `url`
 * @param options.specs {Record<string, unknown>}   its `specs` member
 * @param options.spec {string}   the specification's identifier
 * @param options.supported {string[]}   the versions this client speaks,
 *   newest first
 * @returns {ServiceDescriptionVersionEntry}
 * @throws {IncompatibleServerError}   when no entry names a supported version,
 *   or the chosen entry's `features` is malformed
 */
function requireEntry({
  url,
  specs,
  spec,
  supported
}: {
  url: string
  specs: Record<string, unknown>
  spec: string
  supported: string[]
}): ServiceDescriptionVersionEntry {
  const chosen = chooseEntry({ specs, spec, supported })
  if (chosen === undefined) {
    const offered = versionEntries({ specs, spec }).map(entry => entry.version)
    throw new IncompatibleServerError(
      `The server at "${url}" lists no version of ` +
        `${spec} this client speaks (offered: ` +
        `${offered.length === 0 ? 'none' : offered.join(', ')}; supported: ` +
        `${supported.join(', ')}).`
    )
  }
  if (!hasWellFormedFeatures(chosen)) {
    throw new IncompatibleServerError(
      `The ${spec} ${chosen.version} entry's \`features\` is not an ` +
        'array of strings.'
    )
  }
  return chosen
}

/**
 * Applies the spec's version-selection rules to a service description. A
 * `specs` key the client does not know is ignored, a version entry without a
 * string `version` is ignored, and under each key it knows the newest version
 * this client speaks is chosen. The server must list such a version under
 * both the PWS identifier and the zCap authorization profile's, and is
 * refused otherwise. A companion specification
 * ({@link SUPPORTED_COMPANION_VERSIONS}) is optional, so a server that lists
 * no version of one the client speaks has no chosen entry for it. The members
 * the client acts on are checked before they are used: the PWS entry's
 * `spaces` must be an absolute `http(s)` URL and each chosen entry's
 * `features` an array of strings. A malformed `features` refuses the server
 * on a required entry, and on a companion entry it reads as no entry.
 *
 * @param description {unknown}   the parsed service description
 * @returns {ServiceInfo}
 * @throws {IncompatibleServerError}   when the document lacks `url` or `specs`,
 *   when no PWS entry or no authorization profile entry names a version this
 *   client speaks, or when the `spaces` or `features` of one of those two
 *   entries is malformed
 */
export function selectServiceVersion(description: unknown): ServiceInfo {
  if (
    !isObject(description) ||
    typeof description.url !== 'string' ||
    !isObject(description.specs)
  ) {
    throw new IncompatibleServerError(
      'The service description is not a JSON object with `url` and `specs`.'
    )
  }
  const { url, specs } = description
  const chosen: PwsVersionEntry = requireEntry({
    url,
    specs,
    spec: PWS_SPEC_ID,
    supported: SUPPORTED_PWS_VERSIONS
  })
  const authzProfile: AuthzProfileVersionEntry = requireEntry({
    url,
    specs,
    spec: AUTHZ_PROFILE_SPEC_ID,
    supported: SUPPORTED_AUTHZ_PROFILE_VERSIONS
  })
  const { spaces } = chosen as { spaces?: unknown }
  if (
    spaces !== undefined &&
    (typeof spaces !== 'string' || parseAbsoluteHttpUrl(spaces) === null)
  ) {
    throw new IncompatibleServerError(
      `The ${PWS_SPEC_ID} ${chosen.version} entry's \`spaces\` is not an ` +
        'absolute http(s) URL.'
    )
  }
  const entries: ServiceInfo['entries'] = {
    [PWS_SPEC_ID]: chosen,
    [AUTHZ_PROFILE_SPEC_ID]: authzProfile
  }
  for (const [spec, supported] of Object.entries(
    SUPPORTED_COMPANION_VERSIONS
  )) {
    const companion = chooseEntry({ specs, spec, supported })
    if (companion !== undefined && hasWellFormedFeatures(companion)) {
      entries[spec] = companion
    }
  }
  return {
    description: description as unknown as ServiceDescription,
    version: chosen.version,
    entry: chosen,
    entries,
    ...(spaces !== undefined && { spacesUrl: canonicalContainerUrl(spaces) }),
    hasFeature({ spec, feature }: { spec: string; feature: string }): boolean {
      const entry = Object.hasOwn(entries, spec) ? entries[spec] : undefined
      // `features` was checked on every entry kept in `entries`.
      const features = entry?.features as string[] | undefined
      return features?.includes(feature) ?? false
    }
  }
}

/**
 * The statuses that signal a transient failure (rate limiting, or a gateway
 * or server that is temporarily unavailable) rather than an answer about the
 * server's protocol. A lasting refusal such as 501, 505, or 507 is not in
 * this set.
 */
const TRANSIENT_STATUSES = new Set([429, 502, 503, 504])

/**
 * Rejects a discovery step that answered `status` without what discovery
 * needs: with the mapped transport error when the status is transient, since
 * it says nothing about the protocol the server speaks, and with an
 * `IncompatibleServerError` carrying `message` otherwise.
 *
 * @param options {object}
 * @param options.status {number}
 * @param options.requestUrl {string}
 * @param options.message {string}
 * @returns {never}
 */
function refuse({
  status,
  requestUrl,
  message
}: {
  status: number
  requestUrl: string
  message: string
}): never {
  if (TRANSIENT_STATUSES.has(status)) {
    throw mapError({ status, requestUrl })
  }
  throw new IncompatibleServerError(message, { requestUrl })
}

/**
 * Reads the service description at `serviceUrl` with an unsigned `GET` and
 * selects the version to speak. The `GET` does not follow a redirect, so the
 * document is read from the URL named and from no other.
 *
 * A network failure, and a rate limit or temporary outage (429, 502, 503,
 * 504), reject with the mapped transport error, since they say nothing about
 * the protocol the server speaks.
 *
 * @param options {object}
 * @param options.serviceUrl {string}   the service description's URL
 * @returns {Promise<ServiceInfo>}
 * @throws {IncompatibleServerError}   when the document cannot be read or
 *   parsed, `serviceUrl` answers with a redirect, or version selection
 *   refuses it (see {@link selectServiceVersion})
 */
export async function readServiceDescription({
  serviceUrl
}: {
  serviceUrl: string
}): Promise<ServiceInfo> {
  const response = await fetchMapped(serviceUrl, {
    method: 'GET',
    headers: { accept: 'application/json' },
    redirect: 'manual'
  })
  // A browser reports a redirect it did not follow as an opaque response
  // with status 0.
  const redirected =
    response.type === 'opaqueredirect' ||
    (response.status >= 300 && response.status < 400)
  if (redirected) {
    throw new IncompatibleServerError(
      `The service description at "${serviceUrl}" answered with a ` +
        'redirect, which this client does not follow.',
      { requestUrl: serviceUrl }
    )
  }
  if (!response.ok) {
    refuse({
      status: response.status,
      requestUrl: serviceUrl,
      message:
        `The service description at "${serviceUrl}" answered ` +
        `${response.status}.`
    })
  }
  let description: unknown
  try {
    description = await response.json()
  } catch (err) {
    throw new IncompatibleServerError(
      `The service description at "${serviceUrl}" is not valid JSON.`,
      { requestUrl: serviceUrl, cause: err }
    )
  }
  return selectServiceVersion(description)
}

/**
 * Discovers the service description from any URL the server answers and
 * selects the version to speak: an unsigned `HEAD` of `url` for its `service`
 * link (the response status does not matter), then
 * {@link readServiceDescription} of the linked document. The route for a
 * client that holds no base server URL, such as one opened on a single fixed
 * Space.
 *
 * The probe may be redirected within the origin of `url`, and the linked
 * document must be on that origin too. The probed URL may come from an
 * untrusted party, such as the DID document of whoever issued a capability.
 * Its server could otherwise direct the `GET` to any address the client can
 * reach, or learn the status such an address answers a redirected probe with.
 *
 * A network failure, and a rate limit or temporary outage (429, 502, 503,
 * 504) that comes without the link, reject with the mapped transport error,
 * since they say nothing about the protocol the server speaks.
 *
 * @param options {object}
 * @param options.url {string}   any URL the PWS server answers, typically a
 *   Space URL
 * @returns {Promise<ServiceInfo>}
 * @throws {IncompatibleServerError}   when the response carries no `service`
 *   link, the probe was redirected to another origin, the link names another
 *   origin, the linked document cannot be read or parsed, or version
 *   selection refuses it (see {@link selectServiceVersion})
 */
export async function discoverService({
  url
}: {
  url: string
}): Promise<ServiceInfo> {
  const probe = await fetchMapped(url, { method: 'HEAD' })
  const probedUrl = probe.url || url
  // Checked before the status or the headers are read, so the answer of a
  // host the probe was redirected to is not reported.
  if (new URL(probedUrl).origin !== new URL(url).origin) {
    throw new IncompatibleServerError(
      `The probe of "${url}" was redirected to "${probedUrl}", which is on ` +
        'another origin. This client does not discover a server through a ' +
        'redirect to another origin.',
      { requestUrl: url }
    )
  }
  const serviceUrl = serviceLinkTarget({
    header: probe.headers.get('link'),
    baseUrl: probedUrl
  })
  if (serviceUrl === undefined) {
    refuse({
      status: probe.status,
      requestUrl: url,
      message:
        `The response from "${url}" (${probe.status}) carries no ` +
        'rel="service" link, so the server predates PWS v0.5, which this ' +
        'client requires.'
    })
  }
  if (new URL(serviceUrl).origin !== new URL(probedUrl).origin) {
    throw new IncompatibleServerError(
      `The response from "${url}" names the service description ` +
        `"${serviceUrl}", which is on another origin than "${probedUrl}". ` +
        'This client reads a linked service description only from the ' +
        'origin it probed.',
      { requestUrl: url }
    )
  }
  return readServiceDescription({ serviceUrl })
}
