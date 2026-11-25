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
 *
 * A handle built from a Space handle that carries `didUrl` issues the third
 * form: a chain rooted in `urn:zcap:root:<encoded didUrl>` whose link names a
 * DID URL. Such a grant keeps working when the Space moves to another
 * provider. See `didUrlRooted`.
 *
 * A re-delegation under a parent in DID URL form names a DID URL as well.
 * See `didUrlAttenuated`.
 */
import { AUTHZ_PROFILE_SPEC_ID } from '@interop/storage-core'
import { isValidTarget } from '@interop/zcap'
import { dereferencedTarget, type ClientContext } from './request.js'
import { canonicalSpaceUrl } from './layout.js'
import { rootCapabilityId } from './rootCapability.js'
import { NotSupportedError, ValidationError } from '../errors.js'
import type { GrantOptions, IDelegatedZcap, IZcap } from '../types.js'

/**
 * The token a server lists on its authorization profile entry when it accepts
 * a capability whose `invocationTarget` is a DID URL.
 */
const DID_URL_TARGETS_FEATURE = 'did-url-targets'

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
 * Checks the root DID URL a Space handle is given as `didUrl`. The server
 * synthesizes one root capability per such URL, and refuses a root that
 * carries a selector or a fragment or does not end in `/`.
 *
 * @param didUrl {string}
 * @returns {string}   `didUrl`, unchanged
 * @throws {ValidationError}   when `didUrl` is not a DID URL that ends in
 *   `/`, or it carries a selector or a fragment
 */
export function checkedSpaceDidUrl(didUrl: string): string {
  if (
    !didUrl.startsWith('did:') ||
    !didUrl.endsWith('/') ||
    /[?#]/.test(didUrl)
  ) {
    throw new ValidationError(
      `The Space's root DID URL "${didUrl}" must be a DID URL that ends ` +
        'in `/` and carries no selector and no fragment, such as ' +
        '"did:webvh:<scid>:alice.example/".'
    )
  }
  return didUrl
}

/**
 * Roots a grant in the DID URL form of its Space: the root capability id
 * (`urn:zcap:root:<encoded didUrl>`) to parent it on, and the DID URL target
 * to delegate. The target is `didUrl` plus the path of `target` within the
 * Space.
 *
 * Three checks run first, in this order, and nothing is signed when one
 * fails. The Space's server must advertise `did-url-targets`, since a server
 * without it answers such a grant with the masked `not-found`. `didUrl` must
 * dereference to exactly the Space's canonical URL, the rule the server
 * applies to the root. The link's DID URL must dereference to the https URL
 * the grant was asked for. A longer `PathHandler` of the DID document may map
 * that path elsewhere, and the grant would then reach something other than
 * what the handle addresses.
 *
 * `target` may also be given as a DID URL at or beneath `didUrl`. It is then
 * delegated as given, once it dereferences to a URL inside the Space. That is
 * how a path the DID document aliases is granted.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.didUrl {string}     the Space's root DID URL
 * @param options.spaceUrl {string}   the Space's canonical URL
 * @param options.target {string}     the grant target, an https URL at or
 *   beneath the Space or a DID URL at or beneath `didUrl`
 * @returns {Promise<{ parent: string, target: string }>}
 * @throws {NotSupportedError}   when the server does not advertise
 *   `did-url-targets`
 * @throws {ValidationError}   when `didUrl` does not dereference to the
 *   Space, or `target` is outside it, carries a query or a fragment, or
 *   names a DID URL that dereferences elsewhere than asked
 * @throws {TargetDereferenceError}   when a DID URL cannot be dereferenced
 */
async function didUrlRooted(
  context: ClientContext,
  {
    didUrl,
    spaceUrl,
    target
  }: { didUrl: string; spaceUrl: string; target: string }
): Promise<{ parent: string; target: string }> {
  await requireDidUrlTargets(context, spaceUrl)
  checkNoSelector(target)
  const named = target.startsWith('did:')
  if (named && !target.startsWith(didUrl)) {
    throw new ValidationError(
      `Grant target "${target}" is not at or beneath the Space's ` +
        `\`didUrl\` "${didUrl}".`
    )
  }
  // The https URL an https target asks for, in canonical form.
  const wanted = named ? undefined : spaceRooted({ spaceUrl, target }).target
  const rootUrl = await dereferencedTarget(context, didUrl)
  if (rootUrl !== spaceUrl) {
    throw new ValidationError(
      `The Space's \`didUrl\` "${didUrl}" dereferences to "${rootUrl}", not ` +
        `to the Space "${spaceUrl}". No grant was issued.`
    )
  }
  return {
    parent: rootCapabilityId(didUrl),
    target: await didUrlLink(context, {
      base: didUrl,
      baseUrl: spaceUrl,
      target: wanted ?? target
    })
  }
}

/**
 * The DID URL target of a re-delegation under a parent capability in DID URL
 * form. A link beneath such a parent has to name a DID URL too, since the
 * signer and the server both refuse a chain that mixes the two forms.
 *
 * An https `target` is translated: it becomes the parent's DID URL plus the
 * path of `target` beneath the URL the parent's target dereferences to. The
 * result is dereferenced and compared with `target`, because a longer
 * `PathHandler` of the DID document may map that path elsewhere. A DID URL
 * `target` beneath the parent's is delegated as given, once it dereferences
 * to a URL the parent covers. Nothing is signed when a check fails.
 *
 * The server that must advertise `did-url-targets` is the one the parent's
 * target dereferences to, so that check runs after the dereference.
 *
 * A selector is refused on the target, with one exception. Under a parent
 * whose DID URL carries a selector, a DID URL target has to carry the same
 * one, and an https target cannot be translated.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.capability {IZcap}   the parent, whose `invocationTarget`
 *   is a DID URL
 * @param options.target {string}   the grant target, an https URL or a DID
 *   URL
 * @returns {Promise<string>}   the DID URL to delegate
 * @throws {NotSupportedError}   when the server does not advertise
 *   `did-url-targets`
 * @throws {ValidationError}   when `target` is outside what the parent
 *   covers, carries a query or a fragment the parent does not, or translates
 *   to a DID URL that dereferences elsewhere than asked
 * @throws {TargetDereferenceError}   when a DID URL cannot be dereferenced
 */
async function didUrlAttenuated(
  context: ClientContext,
  { capability, target }: { capability: IZcap; target: string }
): Promise<string> {
  const base = capability.invocationTarget
  const named = target.startsWith('did:')
  // A link keeps the selector of its parent, so a DID URL target under a
  // parent that carries one is left to the check below, which requires the
  // two selectors to be identical.
  if (!named || !/[?#]/.test(base)) {
    checkNoSelector(target)
  }
  if (
    named &&
    !isValidTarget({
      invocationTarget: target,
      baseInvocationTarget: base,
      allowTargetAttenuation: true
    })
  ) {
    throw new ValidationError(
      `Grant target "${target}" is not at or beneath the parent ` +
        `capability's target "${base}".`
    )
  }
  // A path cannot be appended to a parent target that carries a selector.
  if (!named && /[?#]/.test(base)) {
    throw new ValidationError(
      `The parent capability's target "${base}" carries a selector, so the ` +
        `grant target "${target}" cannot be translated to a DID URL beneath ` +
        'it. Give the target as a DID URL that carries the same selector.'
    )
  }
  const baseUrl = await dereferencedTarget(context, base)
  await requireDidUrlTargets(context, baseUrl)
  // An https target is held to the server's rule as well: a URL in
  // canonical form, at or beneath what the parent covers.
  if (!named && !isCanonicalBeneath({ url: target, baseUrl })) {
    throw new ValidationError(
      `Grant target "${target}" is not a URL in canonical form at or ` +
        `beneath "${baseUrl}", the URL the parent capability's target ` +
        `"${base}" dereferences to. No grant was issued.`
    )
  }
  return didUrlLink(context, { base, baseUrl, target })
}

/**
 * Refuses a server that does not accept a capability in DID URL form. Such a
 * server answers the grant with the masked `not-found`. The server asked is
 * the one that answers `url`. That is not always the one this client was
 * configured for, since a delegate may hold a grant on a Space at another
 * server.
 *
 * @param context {ClientContext}
 * @param url {string}   the Space's URL, or a URL beneath it
 * @returns {Promise<void>}
 * @throws {NotSupportedError}   when the server does not advertise
 *   `did-url-targets`
 */
async function requireDidUrlTargets(
  context: ClientContext,
  url: string
): Promise<void> {
  const info = await context.serviceAt(url)
  if (
    !info.hasFeature({
      spec: AUTHZ_PROFILE_SPEC_ID,
      feature: DID_URL_TARGETS_FEATURE
    })
  ) {
    throw new NotSupportedError(
      `The server at "${info.description.url}" does not accept a grant in ` +
        `DID URL form: its ${AUTHZ_PROFILE_SPEC_ID} service description ` +
        `entry does not list the \`${DID_URL_TARGETS_FEATURE}\` feature. No ` +
        'grant was issued.'
    )
  }
}

/**
 * Refuses a grant target with a query or a fragment. In DID URL form a query
 * is a selector of the DID document's version, which this client does not
 * issue.
 *
 * @param target {string}
 * @throws {ValidationError}
 */
function checkNoSelector(target: string): void {
  if (/[?#]/.test(target)) {
    throw new ValidationError(
      `Grant target "${target}" carries a query or a fragment, which a ` +
        'grant in DID URL form cannot name.'
    )
  }
}

/**
 * Whether `url` is at or beneath `baseUrl` and in the form a URL parser
 * leaves unchanged. That is the server's rule for the https URL a link
 * covers.
 *
 * @param options {object}
 * @param options.url {string}
 * @param options.baseUrl {string}
 * @returns {boolean}
 */
function isCanonicalBeneath({
  url,
  baseUrl
}: {
  url: string
  baseUrl: string
}): boolean {
  return (
    isValidTarget({
      invocationTarget: url,
      baseInvocationTarget: baseUrl,
      allowTargetAttenuation: true
    }) && new URL(url).href === url
  )
}

/**
 * The DID URL a link in DID URL form names, checked against the https URL it
 * dereferences to. `base` is the DID URL the link sits at or beneath (the
 * root's, or the parent's target), and `baseUrl` is the https URL `base`
 * dereferences to.
 *
 * For an https `target`, the link is `base` plus the path of `target`
 * beneath `baseUrl`, and it must dereference to exactly `target`. A DID URL
 * `target` is the link itself. It may be an alias, so it is held to the
 * server's rule: it dereferences to a URL in canonical form, at or beneath
 * `baseUrl`.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.base {string}
 * @param options.baseUrl {string}
 * @param options.target {string}   a DID URL at or beneath `base`, or an
 *   https URL in canonical form at or beneath `baseUrl`
 * @returns {Promise<string>}
 * @throws {ValidationError}   when the link dereferences elsewhere
 * @throws {TargetDereferenceError}   when the link cannot be dereferenced
 */
async function didUrlLink(
  context: ClientContext,
  { base, baseUrl, target }: { base: string; baseUrl: string; target: string }
): Promise<string> {
  const wanted = target.startsWith('did:') ? undefined : target
  // `base` and `baseUrl` need not agree on a trailing `/` (an alias
  // `.../alias` may dereference to `.../photos/`), so the path beneath
  // `baseUrl` is joined to `base` with exactly one separator.
  let didTarget = target
  if (wanted !== undefined) {
    const beneath = wanted.slice(baseUrl.length)
    didTarget =
      beneath === ''
        ? base
        : `${base.replace(/\/$/, '')}/${beneath.replace(/^\//, '')}`
  }
  const url =
    didTarget === base ? baseUrl : await dereferencedTarget(context, didTarget)
  if (wanted !== undefined && url !== wanted) {
    throw new ValidationError(
      `Grant target "${didTarget}" dereferences to "${url}", not to ` +
        `"${wanted}". No grant was issued.`
    )
  }
  if (wanted === undefined && !isCanonicalBeneath({ url, baseUrl })) {
    throw new ValidationError(
      `Grant target "${didTarget}" dereferences to "${url}", which is not ` +
        `at or beneath "${baseUrl}". No grant was issued.`
    )
  }
  return didTarget
}

/**
 * Delegates a capability per `GrantOptions`, returning the signed zcap to hand
 * off out-of-band. An explicit `capability` (re-delegation of a parent zcap)
 * always wins; otherwise a grant naming its `spaceUrl` is rooted at that
 * Space, so the resulting capability is revocable via `space.revoke()` /
 * `pws.revoke()`; otherwise ezcap roots it at the target's own root
 * capability.
 *
 * Under a `capability` whose target is a DID URL, a `target` is delegated in
 * DID URL form. An https one is translated first (see `didUrlAttenuated`).
 *
 * @param context {ClientContext}
 * @param options {GrantOptions}
 * @returns {Promise<IDelegatedZcap>}
 * @throws {ValidationError}   when neither `target` nor `capability` is given,
 *   so the delegation names nothing to grant; when `spaceUrl` is given
 *   and `target` does not lie at or beneath it; or when `capability` is in
 *   DID URL form and does not cover `target`
 * @throws {NotSupportedError}   when `capability` is in DID URL form, a
 *   `target` is given, and the server does not advertise `did-url-targets`
 * @throws {TargetDereferenceError}   when a DID URL cannot be dereferenced
 */
export async function delegateGrant(
  context: ClientContext,
  options: GrantOptions
): Promise<IDelegatedZcap> {
  const { target, capability, spaceUrl } = options
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
  // A link beneath a parent in DID URL form names a DID URL as well. With no
  // `target` the signer keeps the parent's own. A parent with no target of
  // its own (a stand-in a caller passes through) is left for the signer.
  if (
    capability !== undefined &&
    target !== undefined &&
    capability.invocationTarget?.startsWith('did:')
  ) {
    return signGrant(context, {
      options,
      rooted: {
        parent: capability,
        target: await didUrlAttenuated(context, { capability, target })
      }
    })
  }
  const rooted =
    capability === undefined && target !== undefined && spaceUrl !== undefined
      ? spaceRooted({ spaceUrl, target })
      : { parent: capability, target }
  return signGrant(context, { options, rooted })
}

/**
 * Signs the delegation of a grant whose parent and target are settled.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.options {GrantOptions}   the delegate, actions and expiry
 * @param options.rooted {object}   the parent capability (or root id) and
 *   the `invocationTarget` to delegate
 * @returns {Promise<IDelegatedZcap>}
 */
async function signGrant(
  context: ClientContext,
  {
    options: { to, actions, expires },
    rooted
  }: {
    options: GrantOptions
    rooted: { parent?: IZcap | string; target?: string }
  }
): Promise<IDelegatedZcap> {
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
 * The scoped-grant sugar shared by `Space.grant`, `Collection.grant` and
 * `Resource.grant`: delegates per `GrantOptions` with the grant `target` prefilled from the
 * handle's `url`, the rooting `spaceUrl` from the handle's Space, and the
 * handle's bound `capability`, if any, as the parent for re-delegation.
 * Explicit options win over every prefill.
 *
 * A handle that carries the Space's `didUrl` issues the grant in DID URL
 * form. A parent capability still wins, so `didUrl` does not apply to a
 * re-delegation. Under a parent in DID URL form, such as the bound capability
 * of a handle built from a DID-form grant, the prefilled https target is
 * translated to a DID URL beneath the parent's (see `delegateGrant`). An
 * explicit `spaceUrl` that names another Space is refused, since `didUrl`
 * names the handle's own.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.url {string}            the handle's URL (target fallback)
 * @param options.spaceUrl {string}       the handle's Space (rooting fallback),
 *   in canonical form
 * @param options.options {GrantOptions}  the caller's grant options
 * @param [options.capability] {IZcap}    the handle's bound capability
 * @param [options.didUrl] {string}       the root DID URL of the handle's Space
 * @returns {Promise<IDelegatedZcap>}
 * @throws {ValidationError}   when `didUrl` applies and `options.spaceUrl`
 *   names another Space, or the parent is in DID URL form and does not
 *   cover the target
 * @throws {NotSupportedError}   when the grant is in DID URL form and the
 *   server does not advertise `did-url-targets`
 */
export async function delegateGrantAt(
  context: ClientContext,
  {
    url,
    spaceUrl,
    options,
    capability,
    didUrl
  }: {
    url: string
    spaceUrl: string
    options: GrantOptions
    capability?: IZcap
    didUrl?: string
  }
): Promise<IDelegatedZcap> {
  const parent = options.capability ?? capability
  const target = options.target ?? url
  if (didUrl === undefined || parent !== undefined) {
    return delegateGrant(context, {
      ...options,
      target,
      spaceUrl: options.spaceUrl ?? spaceUrl,
      capability: parent
    })
  }
  if (
    options.spaceUrl !== undefined &&
    canonicalSpaceUrl(options.spaceUrl) !== spaceUrl
  ) {
    throw new ValidationError(
      `This handle issues grants under the \`didUrl\` "${didUrl}" of the ` +
        `Space "${spaceUrl}", so it cannot root one in the Space ` +
        `"${options.spaceUrl}".`
    )
  }
  return signGrant(context, {
    options,
    rooted: await didUrlRooted(context, { didUrl, spaceUrl, target })
  })
}
