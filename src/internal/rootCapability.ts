/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The root capability id grammar and its inverse, with no transport in the
 * graph. A root capability's id encodes its invocation target
 * (`urn:zcap:root:<encoded target>`), so a Space-rooted chain carries the
 * Space URL in its first entry and `spaceUrlOf` reads it back off the chain
 * rather than assembling it from any server root. `rootCapability` builds the
 * object form a revocation invokes, and grant rooting parents an unparented
 * grant on the id form.
 *
 * This module is on the `./paths` entry's graph, so it must stay offline: no
 * import of `request.ts` or of any module that sends. The revocation
 * submission that uses `rootCapability` lives in `revoke.ts`.
 */
import { constants } from '@interop/zcap'
import { canonicalSpaceUrl } from './layout.js'
import { ValidationError } from '../errors.js'
import type { IRootZcap, IZcap } from '../types.js'

const { ZCAP_CONTEXT_URL, ZCAP_ROOT_PREFIX } = constants

/**
 * The root capability id for an invocation target URL
 * (`urn:zcap:root:<encoded target>`) -- the id grammar shared by revocation
 * (which invokes the revocation URL's own root capability in object form) and
 * grant rooting (which parents an unparented grant on its Space's root
 * capability id).
 *
 * @param target {string}   the absolute invocation target URL
 * @returns {string}
 */
export function rootCapabilityId(target: string): string {
  return `${ZCAP_ROOT_PREFIX}${encodeURIComponent(target)}`
}

/**
 * The invocation target a root capability id names: the inverse of
 * {@link rootCapabilityId}. Returns `null` for an id that is not a root
 * capability id, or whose encoded target is malformed.
 *
 * @param id {string}   a capability id
 * @returns {string | null}
 */
export function rootCapabilityTarget(id: string): string | null {
  if (!id.startsWith(ZCAP_ROOT_PREFIX)) {
    return null
  }
  try {
    return decodeURIComponent(id.slice(ZCAP_ROOT_PREFIX.length))
  } catch {
    return null
  }
}

/**
 * Builds the root capability for `target` in **object** form.
 *
 * The object form is load-bearing: `@interop/ezcap` accepts a *string* root
 * capability id only when its invocation target is `https:`, which would break
 * against an `http://localhost` server. Both forms reduce to the same
 * `zcap id="..."` invocation header.
 *
 * `controller` is client-side only -- the server re-derives the real controller
 * when it synthesizes the root capability -- so the caller's own DID is fine.
 *
 * @param options {object}
 * @param options.target {string}       the absolute invocation target URL
 * @param options.controller {string}   the invoking client's DID
 * @returns {IRootZcap}
 */
export function rootCapability({
  target,
  controller
}: {
  target: string
  controller: string
}): IRootZcap {
  return {
    '@context': ZCAP_CONTEXT_URL,
    id: rootCapabilityId(target),
    invocationTarget: target,
    controller
  }
}

/**
 * The id of the root capability a chain starts at: the first entry of the
 * delegation proof's `capabilityChain`, or the `parentCapability` of a
 * capability delegated straight from a root, or the capability's own id when
 * it is a root. `undefined` when the capability carries no proof and no
 * parent that names a root.
 *
 * The delegation proof is the one carrying `capabilityChain`, wherever it
 * sits in a proof set: a capability may also carry an assertion proof, and
 * nothing fixes the order.
 *
 * @param zcap {IZcap}
 * @returns {string | undefined}
 */
function chainRootId(zcap: IZcap): string | undefined {
  if (!('parentCapability' in zcap)) {
    return zcap.id
  }
  const proofs = Array.isArray(zcap.proof) ? zcap.proof : [zcap.proof]
  const delegation = proofs.find(proof => proof?.capabilityChain !== undefined)
  const first = delegation?.capabilityChain?.[0]
  if (typeof first === 'string') {
    return first
  }
  return typeof zcap.parentCapability === 'string'
    ? zcap.parentCapability
    : undefined
}

/**
 * The URL of the Space a capability is rooted in, read off its delegation
 * chain: a Space-rooted capability's chain starts at the Space's root
 * capability, whose id encodes the Space URL. The result is in canonical
 * form.
 *
 * The root's target is taken to be the Space URL. A Space URL has no shape
 * of its own (a Collection URL is an http(s) URL ending in a slash too), so
 * this function cannot tell a chain rooted at a Space from one rooted at a
 * Collection, a Resource, or a Spaces Repository: only the server, which
 * knows its hierarchy, can, and it refuses a revocation whose chain does not
 * root exactly in the Space. What is refused here is a root whose target
 * cannot be a Space URL at all (an origin, a URL with a query, a URN) and a
 * chain that starts at no root capability. A capability this client minted
 * from a handle is always Space-rooted. A bare `was.grant({ target })` with
 * no `spaceUrl`, the mode for a server with no Space hierarchy, roots at
 * its target and is not revocable this way by design.
 *
 * @param zcap {IZcap}   the capability to locate
 * @returns {string}
 * @throws {ValidationError}   when the chain does not start at a root
 *   capability id, or that id names something that cannot be a Space URL
 */
export function spaceUrlOf(zcap: IZcap): string {
  const rootId = chainRootId(zcap)
  const target = rootId === undefined ? null : rootCapabilityTarget(rootId)
  if (target === null) {
    throw new ValidationError(
      `Cannot derive a Space from capability "${zcap.id}": its chain does ` +
        'not start at a root capability id (`urn:zcap:root:...`), so it is ' +
        'not rooted in a Space.'
    )
  }
  try {
    return canonicalSpaceUrl(target)
  } catch (err) {
    throw new ValidationError(
      `Cannot derive a Space from capability "${zcap.id}": its root ` +
        `capability names "${target}", which is not a Space URL.`,
      { cause: err }
    )
  }
}
