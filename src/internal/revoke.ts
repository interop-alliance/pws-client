/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The revocation primitive shared by `pws.revoke()` and `space.revoke()` -- the
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
 * The root capability id grammar this invokes through, and `spaceUrlOf`,
 * live in `rootCapability.ts`, which the `./paths` entry re-exports. They are
 * kept apart from this module so that entry evaluates no transport.
 */
import { spaceRevocationUrl } from './paths.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { rootCapability } from './rootCapability.js'
import { ValidationError } from '../errors.js'
import type { IDelegatedZcap } from '../types.js'

/**
 * Revokes a Space-rooted delegated capability: `POST`s it to
 * `{spaceUrl}zcaps/revocations/:capabilityId`, invoking that URL's own root
 * capability. Resolves on the server's 204.
 *
 * The `action` is deliberately left unset: `send()` defaults it to the HTTP
 * method, and this route expects `POST` (PWS capabilities are scoped by HTTP
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
