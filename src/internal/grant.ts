/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The delegation primitive shared by `pws.grant()` and the `space`/`collection`
 * grant sugar. Maps `GrantOptions` onto `zcapClient.delegate(...)`, normalizing
 * action verbs to uppercase so a lowercase grant (`'get'`) still validates on
 * the server (which matches actions case-sensitively against `'GET'`).
 *
 * An unparented grant that names its Space (`spaceUrl`, which the scoped sugar
 * fills from the handle) is delegated from that **Space's** root capability,
 * with the target carried as an attenuated `invocationTarget`, rather than
 * from the target's own root capability. Both forms grant the same access (the
 * server verifies PWS routes with target attenuation allowed), but only a
 * Space-rooted chain can be revoked -- revocation is Space-scoped, and the
 * endpoint requires the chain to root exactly in the Space (see `revoke.ts`).
 *
 * A bare `pws.grant({ target })` without `spaceUrl` is the other mode, kept
 * on purpose: it delegates from the target's own root capability (ezcap's
 * default). It is the shape for a server at the basic conformance level,
 * which may serve fixed collections, or resources alone, with no Space
 * container to root a chain in. Such a grant cannot be revoked through a
 * Space's revocation endpoint; that is a limitation of that conformance
 * level, not of the client.
 */
import { isValidTarget } from '@interop/zcap'
import type { ClientContext } from './request.js'
import { canonicalSpaceUrl } from './layout.js'
import { rootCapabilityId } from './rootCapability.js'
import { ValidationError } from '../errors.js'
import type { GrantOptions, IDelegatedZcap, IZcap } from '../types.js'

/**
 * Roots a grant in its Space: the root capability id
 * (`urn:zcap:root:<encoded Space URL>`) to parent it on, after checking that
 * `target` lies at or beneath the Space, and the target to delegate. A chain
 * rooted in one Space cannot delegate a target outside it, and the server
 * would refuse the capability at invocation, so the mismatch is refused here
 * by name.
 *
 * The Space itself may be named in either form. The bare (slash-less) form
 * is accepted as the target, as `parseSpaceTarget` accepts it, and is
 * delegated in canonical form: the server verifies a Space-rooted chain
 * against the canonical Space URL, under which the bare form is not an
 * attenuation of the Space but a sibling of it.
 *
 * The id is returned as a string, which `zcapClient.delegate(...)` accepts for a
 * root parent capability. (Its sibling `request(...)` does not, for a non-`https:`
 * target -- hence the object form in `revoke.ts`.)
 *
 * @param options {object}
 * @param options.spaceUrl {string}   the Space to root the grant in
 * @param options.target {string}     the absolute grant target URL
 * @returns {{ parent: string, target: string }}
 * @throws {ValidationError}   when `target` is not at or beneath `spaceUrl`,
 *   or its path is rewritten by URL normalization (a dot segment)
 */
function spaceRooted({
  spaceUrl,
  target
}: {
  spaceUrl: string
  target: string
}): { parent: string; target: string } {
  const canonical = canonicalSpaceUrl(spaceUrl)
  // The check runs against the canonical Space URL, the base the server
  // verifies the chain against, so what passes here is what the server
  // accepts. The bare form is the one exception, matched exactly: as a base
  // it would also admit `{space}?x`, which the server refuses.
  const bare = canonical.slice(0, -1)
  if (
    target !== bare &&
    !isValidTarget({
      invocationTarget: target,
      baseInvocationTarget: canonical,
      allowTargetAttenuation: true
    })
  ) {
    throw new ValidationError(
      `Grant target "${target}" is not at or beneath the Space ` +
        `"${canonical}" the grant would be rooted in.`
    )
  }
  // The prefix check reads the raw string, so a dot segment (`{space}../x`)
  // passes it while naming a path outside the Space once a URL parser
  // normalizes it. The server resolves the request URL that way, so such a
  // target can never be invoked. Refuse a target whose path does not survive
  // normalization unchanged. The query, if any, is left as given.
  const origin = new URL(canonical).origin
  const rawPath = target.slice(origin.length).replace(/[?#].*$/, '')
  if (target !== bare && new URL(target).pathname !== rawPath) {
    throw new ValidationError(
      `Grant target "${target}" has a path that URL normalization rewrites ` +
        '(a dot segment or an unencoded character); give the target in its ' +
        'normalized form.'
    )
  }
  return {
    parent: rootCapabilityId(canonical),
    target: target === bare ? canonical : target
  }
}

/**
 * Delegates a capability per `GrantOptions`, returning the signed zcap to hand
 * off out-of-band. An explicit `capability` (re-delegation of a parent zcap)
 * always wins; otherwise a grant naming its `spaceUrl` is rooted at that
 * Space, so the resulting capability is revocable via `space.revoke()` /
 * `pws.revoke()`; otherwise ezcap roots it at the target's own root
 * capability.
 *
 * @param context {ClientContext}
 * @param options {GrantOptions}
 * @returns {Promise<IDelegatedZcap>}
 * @throws {ValidationError}   when neither `target` nor `capability` is given,
 *   so the delegation names nothing to grant; or when `spaceUrl` is given
 *   and `target` does not lie at or beneath it
 */
export async function delegateGrant(
  context: ClientContext,
  { to, actions, expires, target, capability, spaceUrl }: GrantOptions
): Promise<IDelegatedZcap> {
  // The scoped sugar always prefills `target`, so this only catches a direct
  // `pws.grant()`. Without either member ezcap has no invocation target and no
  // parent to take one from, and rejects the call with a bare `TypeError` a
  // consumer catching `PwsError` would miss.
  if (target === undefined && capability === undefined) {
    throw new ValidationError(
      'A grant needs a `target` (the invocationTarget URL to grant) or a ' +
        '`capability` (the parent capability to attenuate); neither was given.'
    )
  }
  const rooted =
    capability === undefined && target !== undefined && spaceUrl !== undefined
      ? spaceRooted({ spaceUrl, target })
      : { parent: capability, target }
  return context.zcapClient.delegate({
    controller: to,
    invocationTarget: rooted.target,
    allowedActions: actions.map(action => action.toUpperCase()),
    expires,
    capability: rooted.parent
  })
}

/**
 * Whether a capability permits `action`, matched case-insensitively against
 * its `allowedAction` (a single verb or a list). A capability that states no
 * `allowedAction`, or an empty one, permits every action, as the zcap model
 * reads it.
 *
 * @param options {object}
 * @param [options.zcap] {IZcap}   the capability; `undefined` is read as
 *   unrestricted, for a handle bound to no capability
 * @param options.action {string}   the action verb (e.g. `'GET'`)
 * @returns {boolean}
 */
export function allowsAction({
  zcap,
  action
}: {
  zcap?: IZcap
  action: string
}): boolean {
  const allowed = zcap?.allowedAction
  if (allowed === undefined) {
    return true
  }
  const actions = Array.isArray(allowed) ? allowed : [allowed]
  if (actions.length === 0) {
    return true
  }
  const wanted = action.toUpperCase()
  return actions.some(entry => entry.toUpperCase() === wanted)
}

/**
 * The scoped-grant sugar shared by `Space.grant` and `Collection.grant`:
 * delegates per `GrantOptions` with the grant `target` prefilled from the
 * handle's `url`, the rooting `spaceUrl` from the handle's Space, and the
 * handle's bound `capability`, if any, as the parent for re-delegation.
 * Explicit options win over every prefill.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.url {string}            the handle's URL (target fallback)
 * @param options.spaceUrl {string}       the handle's Space (rooting fallback)
 * @param options.options {GrantOptions}  the caller's grant options
 * @param [options.capability] {IZcap}    the handle's bound capability
 * @returns {Promise<IDelegatedZcap>}
 */
export async function delegateGrantAt(
  context: ClientContext,
  {
    url,
    spaceUrl,
    options,
    capability
  }: {
    url: string
    spaceUrl: string
    options: GrantOptions
    capability?: IZcap
  }
): Promise<IDelegatedZcap> {
  return delegateGrant(context, {
    ...options,
    target: options.target ?? url,
    spaceUrl: options.spaceUrl ?? spaceUrl,
    capability: options.capability ?? capability
  })
}
