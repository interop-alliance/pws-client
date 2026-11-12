/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A self-refreshing EDV document cipher: `createEdvDocCipher` bound to
 * descriptor acquisition and the once-per-session refresh rule, for a host
 * whose decrypt seam is the cipher itself (a sync engine's `decryptDoc`, a
 * conflict resolver) rather than a row-scanning store.
 *
 * Built, the cipher acquires the collection's descriptor (fetch, cache the
 * success, cached fallback whenever the fetch yields none -- see
 * `acquire.ts`) and constructs the underlying EDV cipher from it; with no
 * descriptor, or a descriptor with no epochs, the build refuses fail-closed
 * (every encrypted collection's descriptor carries an epoch roster from
 * provisioning, so the absence can only mean the install has not landed or
 * the host is lying). When a decrypt throws
 * `UnknownEpochError`, the cipher re-acquires the descriptor, rebuilds itself,
 * and retries that decrypt exactly once -- and only once per cipher instance,
 * which the host scopes to one `(profile, collection)` session by dropping
 * its cipher cache when the session ends. A second failure (or any unknown
 * epoch after the one refresh is spent) propagates. A refresh that itself
 * fails does not count as spent -- the original `UnknownEpochError` is
 * rethrown and a later decrypt may try again.
 *
 * Only `UnknownEpochError` drives that refresh, and by design. The client
 * splits the two ways a decrypt can find no key: an epoch the descriptor does
 * not list at all raises `UnknownEpochError`, because a fresher descriptor may
 * well list it; an epoch the descriptor does list but this reader holds no key
 * for raises `KeyUnwrapError` (never a recipient, or removed and the epoch
 * rotated). The second is rethrown immediately, with the refresh left
 * untouched, since re-reading the same descriptor cannot produce a key the
 * reader was not given.
 *
 * A write has the same one refresh, counted apart from the read's. A cipher
 * built while this reader was off the current epoch (it had been removed, or
 * the fetch failed and an older cached descriptor answered) refuses `encrypt`
 * and `encryptUpdate` with `NotCurrentRecipientError`. The first such refusal
 * re-acquires the descriptor, rebuilds, and retries that write once, so a
 * reader re-added since writes again. Still off the current epoch after the
 * refresh, the refusal propagates, and so does every later one for this
 * cipher instance, without another descriptor read.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { NotCurrentRecipientError, UnknownEpochError } from '../errors.js'
import { createEdvDocCipher, type EdvDocCipher } from './docCipher.js'
import {
  acquireDescriptor,
  type EncryptionDescriptorCache,
  type EncryptionDescriptorSource
} from './acquire.js'

/**
 * Builds an {@link EdvDocCipher} whose descriptor is acquired through the
 * source/cache seams and refreshed (once per instance) on an unknown-epoch
 * decrypt or `isPendingStub`, and once more on a write refused because this
 * reader is off the current epoch. The metadata last installed with `applyMeta` is
 * re-applied to the rebuilt cipher, so a refresh keeps the index schema.
 *
 * With no `source` the descriptor is served from the cache alone and the
 * refresh path is inert (an unknown-epoch decrypt propagates immediately) --
 * the shape for a purely local code path that must never touch the network.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault key pair this
 *   collection's envelopes are sealed to
 * @param options.keyResolver {IKeyResolver}
 * @param options.collectionId {string}
 * @param [options.spaceUrl] {string}   the PWS Space holding the collection,
 *   which lets a `decrypt` given a request context read a chunked envelope
 * @param [options.idDerivation] {'content' | 'random'}   defaults to
 *   `'content'`
 * @param [options.source] {EncryptionDescriptorSource}
 * @param options.cache {EncryptionDescriptorCache}
 * @param [options.requireGoverned] {boolean}   forwarded to every descriptor
 *   acquisition, the initial build and the unknown-epoch refresh alike (see
 *   `acquireDescriptor`)
 * @param [options.onFetchError] {function}   observes swallowed
 *   descriptor-fetch failures
 * @returns {Promise<EdvDocCipher>}
 */
export async function createRefreshingEdvDocCipher({
  keyAgreementKey,
  keyResolver,
  collectionId,
  spaceUrl,
  idDerivation,
  source,
  cache,
  requireGoverned,
  onFetchError
}: {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  collectionId: string
  spaceUrl?: string
  idDerivation?: 'content' | 'random'
  source?: EncryptionDescriptorSource
  cache: EncryptionDescriptorCache
  requireGoverned?: boolean
  onFetchError?: (err: unknown, info: { collectionId: string }) => void
}): Promise<EdvDocCipher> {
  // The `/meta` value last installed with `applyMeta`, replayed onto a rebuilt
  // cipher so a refresh does not drop the collection's index schema.
  let appliedMeta: { custom?: unknown } | undefined

  const build = async (): Promise<EdvDocCipher> => {
    const encryption = await acquireDescriptor({
      source,
      cache,
      collectionId,
      requireGoverned,
      onFetchError
    })
    if (!encryption) {
      throw new Error(
        `Collection "${collectionId}" has no encryption descriptor available ` +
          '(fetched or cached). Every encrypted collection carries its key ' +
          'epochs from provisioning; refusing to build a cipher without them.'
      )
    }
    const cipher = await createEdvDocCipher({
      keyAgreementKey,
      keyResolver,
      collectionId,
      spaceUrl,
      idDerivation,
      encryption
    })
    if (appliedMeta !== undefined) {
      await cipher.applyMeta(appliedMeta)
    }
    return cipher
  }

  let inner = await build()

  /**
   * Binds one kind of operation to its own descriptor refresh. The returned
   * runner executes an operation on the current inner cipher and, when it
   * throws the error class a fresher descriptor may cure, refreshes the
   * descriptor and retries once.
   *
   * @param stale {function}   the error class the refresh answers:
   *   `UnknownEpochError` for a read, `NotCurrentRecipientError` for a write
   * @returns {function}   the runner
   */
  function refreshingOn(
    stale: typeof UnknownEpochError | typeof NotCurrentRecipientError
  ): <T>(run: (cipher: EdvDocCipher) => Promise<T>) => Promise<T> {
    // The one descriptor refresh this cipher instance (= this collection this
    // session) may spend on this kind of operation: the in-flight or
    // completed re-read, or `null` while it is still unspent. Shared, so
    // concurrent failures ride a single re-read instead of each spending one.
    let refreshed: Promise<void> | null = null
    return async run => {
      try {
        return await run(inner)
      } catch (err) {
        // `instanceof` is safe here and only here: `inner` is built in this
        // package by `createEdvDocCipher`, which raises this package's own
        // class, so no injected seam is crossed. A caller classifying what
        // THIS cipher throws is crossing one, and uses `isUnknownEpochError` /
        // `isKeyUnwrapError` instead.
        if (!(err instanceof stale) || !source) {
          throw err
        }
        if (!refreshed) {
          const attempt = build().then(cipher => {
            inner = cipher
          })
          refreshed = attempt
          // Only a COMPLETED refresh is spent. A rejected one (the description
          // could not be read and no cached copy answered either) un-arms the
          // guard so a later failure of this kind may try again; a successful
          // refresh that still does not cure the operation stays spent for the
          // session, which is what keeps a genuinely foreign envelope from
          // driving a refetch loop.
          attempt.catch(() => {
            if (refreshed === attempt) {
              refreshed = null
            }
          })
        }
        try {
          await refreshed
        } catch {
          // The refresh failed, so nothing new was learned: surface the
          // original error rather than the build failure, so callers
          // classifying on it (the create-loss re-mint) still see the row
          // they exist to repair.
          throw err
        }
        // One retry under the swapped cipher. If the refresh was already
        // spent before this operation began, this re-attempt is local and
        // fails the same way, so a genuinely foreign envelope still surfaces
        // UnknownEpochError without a second description read.
        return run(inner)
      }
    }
  }

  const onUnknownEpoch = refreshingOn(UnknownEpochError)
  // Counted apart from the read's, so an unknown-epoch decrypt earlier in the
  // session does not spend the write's refresh.
  const onNotCurrentRecipient = refreshingOn(NotCurrentRecipientError)

  return {
    encrypt: options =>
      onNotCurrentRecipient(cipher => cipher.encrypt(options)),

    encryptUpdate: options => {
      if (!inner.encryptUpdate) {
        throw new Error(
          `Collection "${collectionId}" cipher has no in-place update.`
        )
      }
      // Every cipher `build` returns carries the in-place update.
      return onNotCurrentRecipient(cipher => cipher.encryptUpdate!(options))
    },

    decrypt: options => onUnknownEpoch(cipher => cipher.decrypt(options)),

    isPendingStub: options =>
      onUnknownEpoch(cipher => cipher.isPendingStub(options)),

    async applyMeta(options) {
      appliedMeta = options
      return inner.applyMeta(options)
    }
  }
}
