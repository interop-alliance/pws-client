/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared write orchestration. `sendEncodedWrite` turns a codec's
 * {@link EncodedWrite} plus a conditional-write precondition into request
 * headers and sends it (the shape `Collection.add` and `Resource.put` would
 * otherwise each re-implement). Two flows layer on top: `insertResource` (the
 * create path behind `Collection.add` -- encode, the minted-id `PUT` vs
 * server-minting `POST` branch, and the precondition selection) and
 * `upsertResource` (the write-by-id path behind `Resource.put` -- the
 * conditional-codec pre-read of the current document, the codec-vs-caller
 * precondition selection, and the masked-404 policy for a document that exists
 * but is not readable with the bound capability).
 *
 * A codec may also answer `encode` with a multi-request `ChunkedWrite` plan
 * rather than an `EncodedWrite`. Both flows run the plan over the
 * signed-request context built here (`codecRequestContext`); the plan owns its
 * own preconditions, pinned to the pre-read `upsertResource` handed the codec.
 */
import type { HttpResponse } from '@interop/http-client'
import type {
  ChunkedWrite,
  CodecRequestContext,
  EncodedWrite,
  ResourceCodec
} from '../codec.js'
import { isChunkedWrite } from '../codec.js'
import { PreconditionFailedError } from '../errors.js'
import type { IZcap, ResourceData } from '../types.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import {
  assertPreconditionAgainstPreRead,
  assertSinglePrecondition,
  encodedPrecondition,
  readEtag,
  writeHeaders,
  namedPrecondition
} from './conditional.js'
import type { WritePrecondition } from './conditional.js'

/**
 * Sends an encoded write (`PUT`/`POST`) to a resource URL, applying the
 * encoded body (`json` or `body`), its content-type, and the conditional-write
 * precondition. A write is never a `read`, so the response is always present
 * (errors throw via `send`).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.url {string}                   the resource URL to write
 * @param options.method {string}                `PUT` or `POST`
 * @param options.encoded {EncodedWrite}         the codec's encoded write
 * @param [options.capability] {IZcap}
 * @param [options.precondition] {WritePrecondition}   conditional-write headers
 * @returns {Promise<HttpResponse>}
 */
export async function sendEncodedWrite(
  context: ClientContext,
  {
    url,
    method,
    encoded,
    capability,
    precondition
  }: {
    url: string
    method: string
    encoded: EncodedWrite
    capability?: IZcap
    precondition?: WritePrecondition
  }
): Promise<HttpResponse> {
  const response = await send(context, {
    url,
    method,
    capability,
    json: encoded.json,
    body: encoded.body,
    headers: writeHeaders({
      contentType: encoded.contentType,
      precondition,
      epoch: encoded.epoch
    })
  })
  return response as HttpResponse
}

/**
 * Builds the {@link CodecRequestContext} core hands a codec that drives its own
 * I/O: the signed-request primitive bound to this handle's capability. The
 * codec never sees the zcap machinery, and the raw `HttpResponse` it gets back
 * matches the `was.request()` escape hatch, which is what `WasTransport`
 * consumes.
 *
 * Requests go through the same mapped `send` path the core write paths use, so
 * a codec-driven write fails with the typed `WasError` subclasses the calling
 * method documents (a document `PUT` that 404s is a `NotFoundError`, not a raw
 * ky/ezcap error). The typed errors carry the HTTP `status`, so a consumer that
 * dispatches on status keeps working.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param [options.capability] {IZcap}     capability attached to each request
 * @returns {CodecRequestContext}
 */
export function codecRequestContext(
  context: ClientContext,
  { capability }: { capability?: IZcap } = {}
): CodecRequestContext {
  return {
    async request(input) {
      // `send` only resolves `null` for the `read`/`idempotent` flags, which
      // this surface never sets, so the response is always present.
      const response = await send(context, { capability, ...input })
      return response as HttpResponse
    }
  }
}

/**
 * The outcome of {@link insertResource}: either the ordinary single-request
 * write (the codec's encoding, the URL written, and the response) or the
 * result of a codec's multi-request {@link ChunkedWrite} plan, which has no one
 * canonical response.
 */
export type InsertOutcome =
  | {
      chunked?: false
      encoded: EncodedWrite
      url: string
      response: HttpResponse
    }
  | {
      chunked: true
      id: string
      url: string
      contentType?: string
      etag?: string
    }

/**
 * Creates a resource with a codec-minted or server-minted id (insert) through
 * its codec, owning the create orchestration in one place: the encode, the
 * `PUT`-vs-`POST` branch, and the precondition selection.
 *
 * A codec may also answer the encode with a multi-request plan (the EDV codec's
 * chunked blob write). The plan is then executed over the handle's signed
 * request context instead of being sent as one request; it owns its own
 * preconditions.
 *
 * A codec that mints its own id (e.g. the encrypting codec's EDV id) writes it
 * by `PUT` to that id's URL; a codec that mints none (the identity codec)
 * `POST`s to the items URL and lets the server mint one. A conditional codec
 * computes the precondition itself (the EDV codec guards its fresh insert with
 * `If-None-Match: *`); an insert through a non-conditional codec is
 * unconditional, since `add()` names no target revision to pin against.
 *
 * Returns the codec's encoded write and the URL actually written alongside the
 * response, so the caller can shape its result (the created id and URL) without
 * re-deriving either.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.itemsUrl {string}       the collection's items URL, the
 *   `POST` target when the codec mints no id
 * @param options.urlForId {function}     builds the resource URL for a
 *   codec-minted id
 * @param options.codec {ResourceCodec}    the collection's resolved codec
 * @param options.data {ResourceData}      the plaintext value
 * @param [options.contentType] {string}   caller-supplied content type
 * @param [options.capability] {IZcap}
 * @returns {Promise<InsertOutcome>}
 */
export async function insertResource(
  context: ClientContext,
  {
    itemsUrl,
    urlForId,
    codec,
    data,
    contentType,
    capability
  }: {
    itemsUrl: string
    urlForId: (id: string) => string
    codec: ResourceCodec
    data: ResourceData
    contentType?: string
    capability?: IZcap
  }
): Promise<InsertOutcome> {
  const write = await codec.encode({ data, contentType })
  if (isChunkedWrite(write)) {
    const { id, etag } = await write.execute(
      codecRequestContext(context, { capability })
    )
    return {
      chunked: true,
      id,
      url: urlForId(id),
      contentType: write.resourceContentType,
      ...(etag !== undefined && { etag })
    }
  }
  const encoded = write
  const chosen = codec.conditionalWrites
    ? encodedPrecondition(encoded)
    : undefined
  const url = encoded.id !== undefined ? urlForId(encoded.id) : itemsUrl
  const response = await sendEncodedWrite(context, {
    url,
    method: encoded.id !== undefined ? 'PUT' : 'POST',
    capability,
    encoded,
    precondition: chosen
  })
  return { encoded, url, response }
}

/**
 * Creates or replaces a resource by id (upsert) through its codec, owning the
 * conditional-write orchestration in one place:
 *
 * - A conditional codec (e.g. the EDV codec) needs the current stored document
 *   to advance its sequence and pin the write to the current ETag, so the
 *   current document is pre-read; the codec then computes the precondition
 *   itself. A plaintext codec needs no pre-read and defers to the caller's
 *   explicit precondition.
 * - The pre-read cannot distinguish "absent" from "unreadable with this
 *   capability" (WAS masks unauthorized reads as 404), so a conditional codec
 *   encodes a fresh insert (`If-None-Match: *`) in both cases. When the target
 *   in fact exists, the server rejects that insert with 412; that 412 is
 *   re-thrown here with a message naming the real cause, instead of surfacing
 *   as an inexplicable failed create. Conditional codecs therefore need read
 *   access to update an existing document.
 * - A codec may answer with a multi-request `ChunkedWrite` plan (the EDV
 *   codec's large binary write, or any write over a document whose bytes live
 *   in chunk resources). The plan runs over the handle's signed-request
 *   context and owns its preconditions: with no document at this id it
 *   creates one, guarded like any fresh insert, so a 412 surfaces as
 *   `PreconditionFailedError` under the same masked-404 message; over an
 *   existing document it replaces it, pinned to the pre-read's validator, so
 *   a 412 is the ordinary lost-update signal.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.url {string}                   the resource URL to write
 * @param options.codec {ResourceCodec}          the collection's resolved codec
 * @param options.id {string}                    the resource id
 * @param options.data {ResourceData}            the plaintext value
 * @param [options.contentType] {string}         caller-supplied content type
 * @param [options.capability] {IZcap}
 * @param [options.precondition] {WritePrecondition}   the caller's explicit
 *   precondition (used only for a non-conditional codec)
 * @returns {Promise<{ etag?: string }>}   the stored resource's new ETag
 */
export async function upsertResource(
  context: ClientContext,
  {
    url,
    codec,
    id,
    data,
    contentType,
    capability,
    precondition: callerPrecondition
  }: {
    url: string
    codec: ResourceCodec
    id: string
    data: ResourceData
    contentType?: string
    capability?: IZcap
    precondition?: WritePrecondition
  }
): Promise<{ etag?: string }> {
  // An empty precondition object (the handle's default) names no baseline.
  const precondition = namedPrecondition(callerPrecondition)
  // Checked before the pre-read, whose comparison would otherwise answer the
  // pair with a 412 either way.
  assertSinglePrecondition(precondition)
  let current: HttpResponse | null | undefined
  if (codec.conditionalWrites) {
    current = await send(context, {
      url,
      method: 'GET',
      capability,
      read: true
    })
    // The caller's own compare-and-swap baseline is checked against what the
    // pre-read just observed, so a lost race fails here rather than being
    // encoded into a sequence advance the server would then reject.
    assertPreconditionAgainstPreRead({ url, current, precondition })
  }
  const write = await codec.encode({
    id,
    data,
    contentType,
    current,
    // Hand a conditional codec the caller's baseline so it pins the write to
    // that revision instead of to the one its own pre-read observed.
    ...(codec.conditionalWrites &&
      precondition !== undefined && {
        precondition
      })
  })
  if (isChunkedWrite(write)) {
    return await runChunkedPlan(context, {
      url,
      write,
      capability,
      current
    })
  }
  const encoded = write
  // A conditional codec computes the precondition itself (from the sequence /
  // ETag, or from the caller's baseline handed to `encode` above); a plaintext
  // codec defers to the caller's explicit options.
  const chosen = codec.conditionalWrites
    ? encodedPrecondition(encoded)
    : precondition
  try {
    const response = await sendEncodedWrite(context, {
      url,
      method: 'PUT',
      capability,
      encoded,
      precondition: chosen
    })
    return { etag: readEtag(response) }
  } catch (err) {
    if (
      err instanceof PreconditionFailedError &&
      codec.conditionalWrites &&
      current === null
    ) {
      throw maskedInsertRejected({ err, url })
    }
    throw err
  }
}

/**
 * Runs a codec's multi-request plan for a write by id. The plan owns its
 * preconditions, pinned to the pre-read the codec was handed: it creates the
 * resource where the pre-read found none, and replaces the stored document
 * otherwise. This layer knows nothing about how the codec stores things.
 *
 * After a pre-read that found nothing, the plan's first write is
 * create-if-absent, so a 412 means the id was taken after the pre-read, or is
 * held by a document the capability cannot read. It surfaces as
 * `PreconditionFailedError` with the masked-404 message of any other fresh
 * insert by id. After a pre-read that found a document, a 412 is the ordinary
 * lost-update signal and passes through as the plan raised it.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.url {string}   the resource URL the plan writes
 * @param options.write {ChunkedWrite}   the codec's plan
 * @param [options.capability] {IZcap}
 * @param options.current {HttpResponse | null | undefined}   the pre-read's
 *   result, `undefined` when the codec asked for none
 * @returns {Promise<{ etag?: string }>}   the stored resource's new ETag
 */
async function runChunkedPlan(
  context: ClientContext,
  {
    url,
    write,
    capability,
    current
  }: {
    url: string
    write: ChunkedWrite
    capability?: IZcap
    current: HttpResponse | null | undefined
  }
): Promise<{ etag?: string }> {
  try {
    const { etag } = await write.execute(
      codecRequestContext(context, { capability })
    )
    return { etag }
  } catch (err) {
    // A `null` pre-read means a conditional codec looked and found nothing,
    // so the plan wrote create-if-absent.
    if (err instanceof PreconditionFailedError && current === null) {
      throw maskedInsertRejected({ err, url })
    }
    throw err
  }
}

/**
 * The error for a fresh insert by id the server rejected with 412 after the
 * pre-read found nothing: either a concurrent writer created the document
 * since, or it already existed but is not readable with this capability (a
 * masked 404). The client cannot tell the two apart, so the message names
 * both and leads with the remedy that fits both. The server's error is kept
 * as the cause.
 *
 * @param options {object}
 * @param options.err {PreconditionFailedError}   the server's 412
 * @param options.url {string}   the resource URL written
 * @returns {PreconditionFailedError}
 */
function maskedInsertRejected({
  err,
  url
}: {
  err: PreconditionFailedError
  url: string
}): PreconditionFailedError {
  const { status, type, title, details, requestUrl } = err
  return new PreconditionFailedError(
    `Cannot write the document at "${url}": the pre-read found nothing, so ` +
      'the write was sent as a fresh insert, and the server rejected it ' +
      'because a document now exists there. Re-read and retry. Either a ' +
      'concurrent writer created the document after the pre-read, or it ' +
      'already existed and its current version is not readable with this ' +
      'capability (WAS masks unauthorized reads as 404); in that case a ' +
      'conditional codec (e.g. the EDV codec) needs read access to update ' +
      'it.',
    { status, type, title, details, requestUrl, cause: err }
  )
}
