/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Overlaps codec resolution with the signed request it decodes, which every
 * read on a handle needs: the request is the same whatever the codec turns out
 * to be, so the two round trips are independent and there is no reason to pay
 * for them in series.
 *
 * The await order is the load-bearing part. The codec is awaited first so a
 * codec failure takes precedence over a read failure, and the handler
 * attached to the request keeps an abandoned read from surfacing as an
 * unhandled rejection when the codec throws. The request is still awaited
 * afterwards, so its own error is never swallowed.
 *
 * When the codec rejects, the read is abandoned, and its response body is
 * cancelled as soon as the response arrives. A JSON body is already drained
 * by the request layer, so this matters for a non-JSON body (a large blob read
 * through `Resource.getWithEtag`, say), which would otherwise hold its
 * connection open until garbage collection.
 */
import type { ResourceCodec } from '../codec.js'

/**
 * Runs a codec resolution and an independent request concurrently, returning
 * both once they settle.
 *
 * @param codecPromise {Promise<ResourceCodec>}   the codec being resolved
 * @param responsePromise {Promise<Read>}   the request to overlap with it
 * @returns {Promise<[ResourceCodec, Read]>}
 */
export async function withCodec<Read extends Abandonable>(
  codecPromise: Promise<ResourceCodec>,
  responsePromise: Promise<Read>
): Promise<[ResourceCodec, Read]> {
  responsePromise.catch(() => {})
  codecPromise.catch(() => {
    responsePromise.then(cancelBody, () => {})
  })
  const codec = await codecPromise
  const response = await responsePromise
  return [codec, response]
}

/**
 * What an abandoned read must look like for its body to be released: a
 * `fetch`-shaped response, or `null` for a masked 404.
 */
type Abandonable = {
  body?: ReadableStream<Uint8Array> | null
  bodyUsed?: boolean
} | null

/**
 * Cancels the body stream of an abandoned response, if it has one that is
 * still unread. A cancel that itself rejects (a stream locked by another
 * reader) is ignored: the read is abandoned either way.
 *
 * @param response {Abandonable}   the settled read
 * @returns {void}
 */
function cancelBody(response: Abandonable): void {
  if (response?.body && !response.bodyUsed) {
    response.body.cancel().catch(() => {})
  }
}
