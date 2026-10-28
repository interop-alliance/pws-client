/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The revocation primitive shared by `was.revoke()` and `space.revoke()` -- the
 * inverse of `grant.ts`. Submits a delegated capability to its Space's
 * revocation endpoint (`POST {spaceUrl}zcaps/revocations/:capabilityId`),
 * where the URL names the capability's `id` and the body is that capability
 * verbatim, proof and capability chain included.
 *
 * The submission invokes the revocation URL's **own** root capability, whose
 * controller the server synthesizes as every controller in the to-be-revoked
 * capability's delegation chain. That chain is dereferenced root-first, so it
 * includes the root capability -- whose controller is the Space controller.
 * A single invocation therefore authorizes both legitimate callers of the
 * server's dual-root rule ("the delegator revokes" and "a delegee revokes its
 * own capability"), with no need to know which one this client is.
 *
 * A chain that no longer verifies (tampered, expired, or a delegating key
 * gone from its controller document) synthesizes an empty controller set, so
 * the invocation is denied.
 *
 * This module also owns the root capability id grammar and its inverse. A
 * Space-rooted chain starts at the Space's root capability, whose id encodes
 * the Space URL, so the Space a capability belongs to is read off its chain
 * (`spaceUrlOf`) rather than assembled from any server root.
 */
import { canonicalSpaceUrl, spaceRevocationUrl } from './paths.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { ValidationError } from '../errors.js'
import type { IDelegatedZcap, IRootZcap, IZcap } from '../types.js'

/**
 * The zcap JSON-LD context URL, the sole `@context` of a root capability.
 */
const ZCAP_CONTEXT_URL = 'https://w3id.org/zcap/v1'

/**
 * The prefix of a root capability id.
 */
const ROOT_ID_PREFIX = 'urn:zcap:root:'

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
  return `${ROOT_ID_PREFIX}${encodeURIComponent(target)}`
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
  if (!id.startsWith(ROOT_ID_PREFIX)) {
    return null
  }
  try {
    return decodeURIComponent(id.slice(ROOT_ID_PREFIX.length))
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
 * from a handle is always Space-rooted; a bare `was.grant()` with no
 * `spaceUrl` is not.
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

/**
 * Revokes a Space-rooted delegated capability: `POST`s it to
 * `{spaceUrl}zcaps/revocations/:capabilityId`, invoking that URL's own root
 * capability. Resolves on the server's 204.
 *
 * The `action` is deliberately left unset: `send()` defaults it to the HTTP
 * method, and this route expects `POST` (WAS capabilities are scoped by HTTP
 * method, unlike the webkms `/kms` revocation route's `write`).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceUrl {string}          the Space the capability is rooted in
 * @param options.zcap {IDelegatedZcap}      the capability to revoke
 * @returns {Promise<void>}
 */
export async function submitRevocation(
  context: ClientContext,
  { spaceUrl, zcap }: { spaceUrl: string; zcap: IDelegatedZcap }
): Promise<void> {
  if (!('parentCapability' in zcap)) {
    throw new ValidationError(
      'A root capability cannot be revoked; only a delegated capability can.'
    )
  }
  const url = spaceRevocationUrl({ spaceUrl, capabilityId: zcap.id })
  await send(context, {
    url,
    method: 'POST',
    capability: rootCapability({
      target: url,
      controller: context.controllerDid
    }),
    json: zcap
  })
}
