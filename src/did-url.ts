/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `./did-url` entry: the built-in dereferencer of a capability target
 * that is a `did:webvh` DID URL, such as
 * `did:webvh:<scid>:alice.example/photos/cat.jpg`. A grant may name such a
 * target so that it keeps working when the Space moves to another provider.
 * The request is still an https request, so the signer has to find the https
 * URL the DID URL names.
 *
 * The mapping is `dereference` of `@interop/did-method-webvh`. It resolves
 * the DID's document, at the version a selector on the target names, selects
 * the `PathHandler` service whose `path` is the longest complete match of the
 * DID URL path, and appends the rest of the path to that service's
 * `serviceEndpoint`.
 *
 * This is the one entry that loads the DID library. The main entry reaches it
 * through a dynamic `import()`, and only when a request carries a DID URL
 * target and the client was given no `dereferenceTarget` of its own.
 */
import { dereference } from '@interop/did-method-webvh'
import { checkDereferencedTarget } from '@interop/ezcap'
import type { FetchLike } from '@interop/did-method-webvh'

import { TargetDereferenceError, errorMessage } from './errors.js'
import { Memo } from './internal/memo.js'
import type { DereferenceTarget } from './types.js'

export { TargetDereferenceError } from './errors.js'
export type { DereferenceTarget } from './types.js'

/**
 * How long a dereferenced target is served from the cache, in milliseconds.
 * It matches the time a server keeps the document of a DID it does not host.
 */
export const TARGET_CACHE_TTL = 5 * 60 * 1000

/**
 * Builds a `dereferenceTarget` hook that maps a `did:webvh` DID URL to the
 * https URL it dereferences to. Pass the result to `PwsClient` as its
 * `dereferenceTarget` option, or to the hooks of `@interop/ezcap` and
 * `@interop/zcap`.
 *
 * The returned function holds its own cache, keyed by the target string. A
 * dereferenced URL is served from it for {@link TARGET_CACHE_TTL}. Concurrent
 * calls for one target share a single resolution. A failure is not cached, so
 * the next call tries again.
 *
 * A target that is not a `did:` URL is already the URL it names and is
 * returned as it is. Every refusal is a `TargetDereferenceError`. That
 * includes a result ezcap would refuse (not https, or with a query or
 * fragment) and one a URL parser would rewrite, such as a path with a dot
 * segment.
 *
 * @param [options] {object}
 * @param [options.fetch] {FetchLike}   the fetch used to retrieve the DID
 *   log and its witness proofs. Defaults to the global `fetch`
 * @returns {DereferenceTarget}
 */
export function createTargetDereferencer({
  fetch
}: { fetch?: FetchLike } = {}): DereferenceTarget {
  const cache = new Map<string, { url: Memo<string>; expires: number }>()

  return async function dereferenceTarget({ invocationTarget }) {
    if (!invocationTarget.startsWith('did:')) {
      return invocationTarget
    }
    const now = Date.now()
    let entry = cache.get(invocationTarget)
    if (entry === undefined || entry.expires <= now) {
      // Drop every expired entry, so the cache holds only targets in use.
      for (const [target, { expires }] of cache) {
        if (expires <= now) {
          cache.delete(target)
        }
      }
      // The memo shares one resolution among concurrent calls and does not
      // keep a rejection, so the next call for the target tries again.
      entry = {
        url: new Memo(() => mapDidUrl({ target: invocationTarget, fetch })),
        expires: now + TARGET_CACHE_TTL
      }
      cache.set(invocationTarget, entry)
    }
    try {
      return await entry.url.get()
    } catch (err) {
      // A failed entry is dropped, so the dereference that succeeds later
      // is kept for a full lifetime of its own.
      if (cache.get(invocationTarget) === entry) {
        cache.delete(invocationTarget)
      }
      throw err
    }
  }
}

/**
 * Maps one `did:webvh` DID URL to the URL it dereferences to, with no cache.
 *
 * @param options {object}
 * @param options.target {string}   the DID URL
 * @param [options.fetch] {FetchLike}
 * @returns {Promise<string>}
 * @throws {TargetDereferenceError}
 */
async function mapDidUrl({
  target,
  fetch
}: {
  target: string
  fetch?: FetchLike
}): Promise<string> {
  if (!target.startsWith('did:webvh:')) {
    throw new TargetDereferenceError(`"${target}" is not a did:webvh DID URL.`)
  }
  // `dereference` would carry a fragment over to the URL, and a request URL
  // has none. So a fragment is refused, an empty one included.
  if (target.includes('#')) {
    throw new TargetDereferenceError(
      `The DID URL "${target}" carries a fragment.`
    )
  }
  // `dereference` parses the DID URL before it fetches anything, so a target
  // with no path or an unsupported parameter is refused with no request.
  try {
    const url = await dereference(target, { fetch })
    // The rule ezcap applies to a hook's result, applied here so a refusal
    // is a `TargetDereferenceError` as every other one is.
    checkDereferencedTarget({ dereferencedTarget: url })
    // A URL parser removes dot segments and rewrites a backslash, so such a
    // URL could name a resource outside the prefix it appears to carry.
    if (new URL(url).href !== url) {
      throw new Error(
        `It dereferences to "${url}", which is not in canonical form.`
      )
    }
    return url
  } catch (err) {
    throw new TargetDereferenceError(
      `The DID URL "${target}" could not be dereferenced: ` + errorMessage(err),
      { cause: err }
    )
  }
}
