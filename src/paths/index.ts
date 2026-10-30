/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/pws-client/paths` subpath entry: the PWS URL grammar as
 * standalone functions, for a consumer that has to form a URL beneath a Space
 * or a zcap `invocationTarget` without going through a navigational handle.
 *
 * Every builder takes the Space URL the server named (the `Location` of the
 * create response, a listing item's `url`, a stored pointer) and derives one
 * URL beneath it: `collectionUrl({ spaceUrl, collectionId })`,
 * `resourceUrl({ spaceUrl, collectionId, resourceId })`, and the `meta`,
 * `log`, and `query` sub-resources. No builder forms a Space URL, and none
 * takes a server root: the spec places a Space beside nothing, so a Space URL
 * is received rather than assembled. `canonicalSpaceUrl` is the one rule for
 * what a Space URL is, and `spaceIdOfUrl` reads the id off its last segment.
 *
 * The builders own the trailing-slash canonicalization (a trailing slash
 * marks a container in canonical form -- the Space URL, `{spaceUrl}{c}/` --
 * everything else has none, and no two URLs differ only by a trailing slash)
 * and the per-segment percent-encoding, and the zcap `invocationTarget` is
 * derived from the request URL -- so a caller that hand-assembles a URL is
 * re-deriving rules that must match the server's `allowedTarget` byte for
 * byte. Exporting the builders instead is what keeps that from happening. A
 * container's description lives at its `meta` segment (`spaceMetaUrl`,
 * `collectionMetaUrl`) instead of at the container URL. `spaceReplicasUrl`
 * and `replicaRegistrationUrl` form the replicas route and one registration
 * beneath it, for a consumer minting a grant on that route.
 *
 * `parseSpaceTarget` is the inverse grammar (an absolute URL back to the
 * containment depth it addresses beneath a Space), `spaceUrlOf` reads the
 * Space a capability is rooted in off its delegation chain,
 * `isReservedCollectionId` / `isReservedResourceId` report whether a segment
 * is in the Reserved Path Segment Registry (the builders throw on one, so a
 * caller forming a URL out of a value it did not choose asks first), and
 * `rootCapabilityId` / `rootCapabilityTarget` / `rootCapability` mint and
 * read the `urn:zcap:root:` capability a target's own root invocation names
 * -- the id form for parenting an unparented grant, the object form for
 * invoking it (`@interop/ezcap` accepts a bare root capability id only for an
 * `https:` target, which would break against an `http://localhost` server).
 *
 * Kept off the core entry so a consumer opts in; every export here is a pure
 * function with no I/O and no client state.
 */
export {
  spaceMetaUrl,
  collectionUrl,
  collectionMetaUrl,
  collectionLogUrl,
  collectionQueryUrl,
  resourceUrl,
  resourceMetaUrl,
  spaceReplicasUrl,
  replicaRegistrationUrl,
  parseSpaceTarget
} from '../internal/paths.js'
export * from './layout.js'
export {
  isReservedCollectionId,
  isReservedResourceId
} from '../internal/reserved.js'
export type { ParsedSpacePath } from '../internal/paths.js'

export {
  rootCapabilityId,
  rootCapabilityTarget,
  rootCapability,
  spaceUrlOf
} from '../internal/rootCapability.js'
export type { IRootZcap } from '../types.js'
