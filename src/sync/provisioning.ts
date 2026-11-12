/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Idempotent, non-clobbering Space + Collection provisioning for a synced
 * collection. Everything is create-if-absent: an existing Space description,
 * an existing encryption descriptor (which may carry a key-epoch roster other
 * clients encrypt under), and an existing access policy are never overwritten,
 * so ANY controller-tier client -- including one that joined a Space some
 * other wallet provisioned -- can re-run it to heal a torn provisioning run,
 * provided it asks for the mode the collection was provisioned in. On a fully
 * settled Space it issues only reads.
 *
 * This module ensures the CONTAINER only and stays crypto-free: an `'edv'`
 * collection is declared encrypted here, but its key-epoch roster -- which
 * every encrypted collection must carry before any read or write routes
 * (epoch-from-birth) -- is installed by the EDV-bearing second step,
 * `ensureFirstEpoch` in `@interop/pws-client/edv`.
 *
 * Three collection modes: `'edv'` (the client-written encryption descriptor),
 * `'plaintext'` (no descriptor), and `'governed'` (a Collection whose
 * `encryption` member the server derives from its history log). A `'governed'`
 * collection is created descriptor-less here and declared governed afterwards,
 * by the caller's guarded create of the log. The `encryption` member is
 * creation-only on the server, so a standing collection keeps the mode it was
 * created in. A request for a different mode is refused with
 * `ValidationError`. A descriptor-less collection reads the same whether it is
 * plaintext or a governed one whose log is not created yet, so both of those
 * modes accept it and `'edv'` is refused over it.
 */
import type {
  CollectionEncryption,
  CollectionGenerator,
  IZcap,
  SpaceMetadata
} from '../types.js'
import type { PwsClient } from '../PwsClient.js'
// A direct module import (not the `./edv` subpath entry), so the crypto-free
// sync module does not pull the EDV crypto graph for one number.
import { EDV_SCHEME_VERSION } from '../edv/constants.js'
import { ValidationError, PwsError } from '../errors.js'
import { isGovernedDescriptor } from '../internal/describe.js'

/**
 * The Space display name applied at creation when the caller names none.
 */
const DEFAULT_SPACE_NAME = 'PWS Space'

/**
 * The encryption descriptor a fresh collection is created with when the caller
 * asks for `encryption: 'edv'`.
 */
const EDV_DESCRIPTOR = { scheme: 'edv', version: EDV_SCHEME_VERSION } as const

/**
 * Compares the mode a caller asked for with the `encryption` member a standing
 * collection serves, and says why the two disagree. The member is
 * creation-only on the server, so a disagreement cannot be repaired by a write
 * from here.
 *
 * A descriptor-less collection satisfies both `'plaintext'` and `'governed'`:
 * a governed collection is created without the member and gains the derived
 * one when its history log is created, so the two are indistinguishable until
 * then.
 *
 * @param options {object}
 * @param options.requested {'edv' | 'plaintext' | 'governed'}   the mode the
 *   caller asked for
 * @param [options.standing] {CollectionEncryption}   the `encryption` member
 *   the standing collection serves, if any
 * @returns {string | undefined}   the reason the standing collection cannot
 *   serve the requested mode, phrased to follow the collection's name; or
 *   `undefined` when it can
 */
function standingModeMismatch({
  requested,
  standing
}: {
  requested: 'edv' | 'plaintext' | 'governed'
  standing?: CollectionEncryption
}): string | undefined {
  if (standing === undefined) {
    if (requested !== 'edv') {
      return undefined
    }
    return (
      'exists without an encryption descriptor, so it cannot be declared ' +
      'encrypted. The descriptor is declared only when a Collection is ' +
      'created. The Collection is either plaintext, or governed with its ' +
      'history log not created yet. If it is governed, provision it with ' +
      "encryption: 'governed'. If it is plaintext, create a new Collection " +
      'and copy its Resources into it.'
    )
  }
  if (isGovernedDescriptor(standing)) {
    if (requested === 'governed') {
      return undefined
    }
    return (
      'is governed by a history log, so it cannot be provisioned as ' +
      `'${requested}'. Provision it with encryption: 'governed'.`
    )
  }
  if (requested === 'edv') {
    return undefined
  }
  if (requested === 'governed') {
    return (
      'carries a client-written encryption descriptor, so it cannot be ' +
      'governed by a history log. The server keeps a declared descriptor ' +
      'immutable.'
    )
  }
  return (
    'carries a client-written encryption descriptor, so it is not ' +
    "plaintext. Provision it with encryption: 'edv'."
  )
}

/**
 * Rethrows a failed provisioning step. A typed client error propagates
 * UNCHANGED, because what a caller does next depends on which one it is: an
 * `AuthRequiredError` (a revoked or expired grant) means stop retrying and
 * prompt for a reconnect, a `ConflictError` (`encryption-immutable`) means the
 * descriptor is already settled by another client, and a `PwsServerError` is
 * worth a retry. Wrapping every failure in a bare `Error` made all of them
 * indistinguishable at the caller. Anything untyped -- which carries no such
 * signal to preserve -- is wrapped with the step's context instead.
 *
 * @param err {unknown}   the caught failure
 * @param context {string}   what the step was trying to do
 * @returns {never}   always throws
 */
function rethrowProvisioningFailure(err: unknown, context: string): never {
  if (err instanceof PwsError) {
    throw err
  }
  throw new Error(context, { cause: err })
}

/**
 * The read-then-guarded-create both ensures share: the value is read and, when
 * present, kept as-is; when absent, `create` runs the `If-None-Match: *` write,
 * and when that fails for ANY reason the value is re-read, and a value now
 * present is adopted as the winner of a create race instead of failing. The
 * race is detected by the re-read rather than by the failure's status because
 * the server answers a lost race with whatever check the rival's description
 * trips first: a 412 from the precondition, but also
 * a 400 or 409 from the encryption-descriptor transition rules when the rival
 * already installed key epochs. When nothing can be read back, the create's
 * own failure is rethrown, so a genuine failure keeps its type.
 *
 * A `create` that resolves `undefined` (a server that answered the create with
 * no body) also falls through to the re-read; that value being unreadable is
 * the one case reported as its own error.
 *
 * @param options {object}
 * @param options.read {function}   reads the value; `null` when absent
 * @param options.create {function}   the guarded write; resolves the created
 *   value, or `undefined` when the server echoed none
 * @param options.unreadable {string}   the error message when a create
 *   succeeded but the value cannot be read back
 * @returns {Promise<{ value: T; created: boolean }>}   the value now present
 *   and whether this call created it
 */
async function readOrCreate<T>({
  read,
  create,
  unreadable
}: {
  read: () => Promise<T | null>
  create: () => Promise<T | undefined>
  unreadable: string
}): Promise<{ value: T; created: boolean }> {
  const current = await read()
  if (current !== null) {
    return { value: current, created: false }
  }
  let created = false
  let failure: unknown
  try {
    const value = await create()
    created = true
    if (value !== undefined) {
      return { value, created }
    }
  } catch (err) {
    failure = err
  }
  let latest: T | null
  try {
    latest = await read()
  } catch (err) {
    // The create failed and the confirming re-read failed too -- usually the
    // same outage. The create's own error is the actionable one (a `412`
    // race, a `409` `encryption-immutable`, an auth refusal), and it is the
    // typed error this whole path exists to preserve, so it wins over the
    // re-read's.
    if (!created) {
      throw failure
    }
    throw err
  }
  if (latest !== null) {
    return { value: latest, created }
  }
  if (created) {
    throw new ValidationError(unreadable)
  }
  throw failure
}

/**
 * Ensures the controller's Space exists and one synced collection is
 * configured, without overwriting anything already there. The Space is
 * described first and created only when absent -- an existing Space keeps
 * its name AND its controller, so `controllerDid` is used only at creation
 * (a joined client re-running this never rewrites the description). The
 * collection likewise: when absent, an `'edv'` collection is created with the
 * encryption descriptor `{ scheme: 'edv', version: EDV_SCHEME_VERSION }`, so
 * the server stores only ciphertext it can never decrypt and validates every
 * write against the declared envelope wire format -- the same version the
 * cipher binds into each envelope's AEAD-protected header, so descriptor and
 * envelopes cannot drift; a `'plaintext'` or `'governed'` collection is created
 * without one. Both creates are guarded (`If-None-Match: *`), so two clients
 * booting at once cannot both create, and the loser adopts the winner's
 * description instead of failing. Against a server that ignores the
 * precondition the create is an unconditional upsert, and the loser of a race
 * can overwrite the winner's display name; the server merges the rest of the
 * winner's description forward.
 *
 * A collection that already stands is never written to, epochs and display
 * name included. The server accepts `encryption` only on the write that
 * creates a Collection, so a standing collection keeps its mode, and a spec
 * that asks for another one throws `ValidationError`:
 *
 * - `'edv'` needs a client-written descriptor (no `history` member). It is
 *   refused over a governed collection and over a descriptor-less one. The
 *   latter is either plaintext, where the way forward is a new collection with
 *   the resources copied into it, or a governed collection whose history log
 *   is not created yet, which a `'governed'` spec provisions.
 * - `'governed'` accepts a descriptor-less collection or one already governed.
 *   It is refused over a client-written descriptor, which the server keeps
 *   immutable (`encryption-immutable`), rather than letting the caller's log
 *   create fail with the server's 409.
 * - `'plaintext'` accepts only a descriptor-less collection.
 *
 * The check runs on the description this call read, so over a collection that
 * stood at the first read nothing is sent. When the collection appeared
 * between that read and the guarded create, the create has already gone out
 * by the time the rival's description is compared. A server that honours
 * `If-None-Match` refused it; one that ignores the precondition applied it as
 * the upsert described above. A public collection gets the collection-level
 * world-read grant (`setPublic`, what makes a resource URL in it resolve for
 * anyone) only when its policy does not already say so. Every request invokes
 * the root capability, or `capability` when the caller holds a delegated one.
 *
 * @param options {object}
 * @param options.pws {PwsClient}
 * @param options.spaceUrl {string}   the Space's URL
 * @param options.controllerDid {string}   the Space controller (e.g. `did:key`);
 *   used only when the Space does not exist yet
 * @param options.collectionId {string}    the PWS collection id
 * @param [options.encryption] {'edv' | 'plaintext' | 'governed'}   how the
 *   collection's `encryption` member is settled; defaults to `'edv'`.
 *   `'edv'` declares the descriptor here, `'plaintext'` declares none, and
 *   `'governed'` leaves the member to the server, which derives it from the
 *   collection's history log. Declaring that governance is the caller's next
 *   step, through the log's guarded create --
 *   `logGovernedDescriptorStore(...).create` or
 *   `resourceLogStore({ collection }).create`
 * @param [options.isPublic] {boolean}   grant collection-level world read
 * @param [options.spaceName] {string}   the Space display name, applied only at
 *   Space creation; defaults to `'PWS Space'`
 * @param [options.collectionName] {string}   the collection display name,
 *   applied only at collection creation; defaults to the collection id
 * @param [options.spaceDescription] {SpaceMetadata}   the Space's
 *   description, when the caller has already ensured the Space (with
 *   {@link ensureSpace}). Supplying it skips the Space half entirely, which is
 *   what keeps a caller provisioning N collections from ensuring one Space N
 *   times over; omit it and the Space is ensured here as before. Its `id` must
 *   be the Space's id (the last path segment of `spaceUrl`); a description
 *   whose id differs throws `ValidationError`, since skipping the ensure
 *   would leave that Space unprovisioned. The id is all a Space description
 *   carries, so a description of a same-named Space elsewhere passes
 * @param [options.capability] {IZcap}   an invocation capability every
 *   request rides (a delegated Space-subtree zcap, say); the root capability
 *   is invoked otherwise. A capability scoped below the bare Space URL cannot
 *   reach the Space half, so a caller holding one supplies `spaceDescription`
 * @param [options.generator] {CollectionGenerator}   the application the
 *   collection is provisioned for (its DID, and optionally the Web origin that
 *   DID was bound to and its canonical URL) -- controller-asserted attribution
 *   the server persists but never verifies. It is stamped on the guarded create
 *   only: a collection that already stands keeps whatever attribution it
 *   carries (or none), so a later ensure naming a different application
 *   cannot rename the creator. A caller that wants to re-attribute a standing
 *   collection writes its Description itself
 * @returns {Promise<{ created: boolean }>}   whether this call's guarded
 *   create made the collection. It is `false` when the collection already
 *   stood, and also when this call lost a create race and adopted the rival's
 *   collection. A caller that must know whether the collection is its own
 *   reads this rather than an earlier description, which a rival can
 *   outrun
 */
export async function ensureSpaceAndCollection({
  pws,
  spaceUrl,
  controllerDid,
  collectionId,
  encryption = 'edv',
  isPublic = false,
  spaceName = DEFAULT_SPACE_NAME,
  collectionName = collectionId,
  spaceDescription,
  capability,
  generator
}: {
  pws: PwsClient
  spaceUrl: string
  controllerDid: string
  collectionId: string
  encryption?: 'edv' | 'plaintext' | 'governed'
  isPublic?: boolean
  spaceName?: string
  collectionName?: string
  spaceDescription?: SpaceMetadata
  capability?: IZcap
  generator?: CollectionGenerator
}): Promise<{ created: boolean }> {
  const space = pws.spaceAt(spaceUrl, { capability })

  if (spaceDescription === undefined) {
    await ensureSpace({ pws, spaceUrl, controllerDid, spaceName, capability })
  } else if (space.id !== undefined && spaceDescription.id !== space.id) {
    // Supplying a description skips the Space half entirely, so a caller
    // holding descriptions for several Spaces that passes the wrong one
    // provisions a collection into a Space this call never ensured. Caught
    // here, that is a misuse with a name; caught later, it is an opaque
    // collection-configure failure.
    throw new ValidationError(
      `Space description id "${spaceDescription.id}" does not name the space ` +
        `being provisioned ("${space.id}").`
    )
  }

  try {
    const collection = space.collection(collectionId)
    // The app attribution as it goes on the wire. Nothing verifies it once
    // it is stored -- the server persists it as written.
    const attribution = generator === undefined ? {} : { generator }
    // A `'governed'` or `'plaintext'` collection takes the descriptor-less
    // create: a governed `encryption` member is the server's to derive.
    const { value: read, created } = await readOrCreate({
      read: () => collection.describeWithEtag(),
      create: () =>
        collection.replaceDescription(
          encryption === 'edv'
            ? {
                name: collectionName,
                encryption: EDV_DESCRIPTOR,
                ...attribution
              }
            : { name: collectionName, ...attribution },
          { ifNoneMatch: true }
        ),
      unreadable:
        `Collection "${collectionId}" in space "${spaceUrl}" was ` +
        'created but cannot be read back.'
    })
    const current = read.description
    // A standing collection keeps the mode it was created in, so a spec
    // that asks for another one is refused, before the world-read grant. On
    // the lost-race path the guarded create has already been sent.
    const mismatch = created
      ? undefined
      : standingModeMismatch({
          requested: encryption,
          standing: current.encryption
        })
    if (mismatch !== undefined) {
      throw new ValidationError(
        `Collection "${collectionId}" in space "${spaceUrl}" ${mismatch}`
      )
    }
    // A collection this call just created has no policy document yet, so the
    // read that would find it non-public is skipped.
    if (isPublic && (created || !(await collection.isPublic()))) {
      await collection.setPublic()
    }
    return { created }
  } catch (err) {
    rethrowProvisioningFailure(
      err,
      `Failed to configure collection "${collectionId}" in space "${spaceUrl}".`
    )
  }
}

/**
 * Ensures the controller's Space exists, without overwriting anything already
 * there -- the Space half of {@link ensureSpaceAndCollection}, split out so a
 * caller provisioning SEVERAL collections into one Space pays for it once
 * rather than once per collection. An existing Space keeps its name AND its
 * controller, so `controllerDid` is used only at creation. The create is
 * guarded (`If-None-Match: *`), so a Space created concurrently keeps its
 * `type` array (accepted at creation only) and is adopted by the loser.
 *
 * Costs one `GET` on a settled Space, and one `GET` plus one guarded `PUT`
 * (`If-None-Match: *`) on a fresh one; a lost create race costs one more `GET`
 * to adopt the winner.
 *
 * @param options {object}
 * @param options.pws {PwsClient}
 * @param options.spaceUrl {string}
 * @param options.controllerDid {string}   the Space controller (e.g.
 *   `did:key`); used only when the Space does not exist yet
 * @param [options.spaceName] {string}   the Space display name, applied only at
 *   Space creation; defaults to `'PWS Space'`
 * @param [options.capability] {IZcap}   an invocation capability both
 *   requests ride; the root capability is invoked otherwise
 * @returns {Promise<SpaceMetadata>}   the Space's description, existing or
 *   just written -- pass it to {@link ensureSpaceAndCollection} as
 *   `spaceDescription` so each collection skips the Space ensure
 */
export async function ensureSpace({
  pws,
  spaceUrl,
  controllerDid,
  spaceName = DEFAULT_SPACE_NAME,
  capability
}: {
  pws: PwsClient
  spaceUrl: string
  controllerDid: string
  spaceName?: string
  capability?: IZcap
}): Promise<SpaceMetadata> {
  const space = pws.spaceAt(spaceUrl, { capability })
  try {
    const { value } = await readOrCreate({
      read: () => space.describe(),
      create: async () =>
        (
          await space.replaceDescription(
            { name: spaceName, controller: controllerDid },
            { ifNoneMatch: true }
          )
        ).description,
      unreadable: `Space "${spaceUrl}" was created but cannot be read back.`
    })
    return value
  } catch (err) {
    rethrowProvisioningFailure(
      err,
      `Failed to configure PWS space "${spaceUrl}" for "${controllerDid}".`
    )
  }
}
