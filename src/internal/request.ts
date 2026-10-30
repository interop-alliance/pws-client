/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The load-bearing transport layer: wraps `zcapClient.request(...)` on an
 * absolute URL, defaulting the capability `action` to the HTTP method (never
 * ezcap's `read`/`write`). `send()` adds the typed-error
 * mapping and the null-on-404 read translation; `rawRequest()` is the
 * unmapped escape hatch used by `pws.request()`. Every signed request first
 * awaits the context's memoized service discovery, so no request reaches a
 * server whose protocol version this client does not speak.
 */
import type { ZcapClient } from '@interop/ezcap'
import { isValidTarget } from '@interop/zcap'
import { httpClient, type HttpResponse } from '@interop/http-client'
import {
  NotFoundError,
  PwsError,
  PwsServerError,
  httpStatus
} from '../errors.js'
import { mapError } from './mapError.js'
import { dataOrNull } from './content.js'
import { readEtag } from './conditional.js'
import type { EncryptionProvider } from '../codec.js'
import type { IZcap, RequestInput, ServiceInfo } from '../types.js'

/**
 * The shared context threaded through every handle: the wrapped ezcap client,
 * the controller DID of its signer, the optional encryption provider that
 * supplies an encrypting codec for the collections the client holds keys
 * for, and the memoized service discovery every signed request waits on.
 *
 * `controllerDid` is a lazy read, not a stored string: `PwsClient` backs it
 * with a getter so that building a context (and therefore a handle) never
 * requires an invocation signer. A client that holds only a delegation signer
 * reads it as a `ValidationError`, at the two operations that actually need
 * it (`createSpace`'s controller default and `rootCapability`'s client-side
 * controller) rather than at construction.
 */
export interface ClientContext {
  zcapClient: ZcapClient
  controllerDid: string
  encryption?: EncryptionProvider
  service: () => Promise<ServiceInfo>
}

/**
 * A single signed request: the public `RequestInput` shape (an absolute
 * `url`) plus the `send()`-level 404 translations.
 */
export interface SendInput extends RequestInput {
  /**
   * When true, a 404 response resolves to `null` instead of throwing.
   */
  read?: boolean
  /**
   * When true, a 404 response resolves to `null` instead of throwing, so a
   * delete of an already-absent target succeeds (idempotent delete).
   */
  idempotent?: boolean
}

/**
 * Signs and sends a request via the wrapped ezcap client, returning the raw
 * `HttpResponse` and throwing the raw ky/ezcap error. Does not apply error
 * mapping or null-on-404 -- this is the escape-hatch primitive. It waits on
 * the context's service discovery first, and rejects with that discovery's
 * error (such as `IncompatibleServerError`) before anything is signed.
 *
 * @param context {ClientContext}
 * @param input {SendInput}
 * @returns {Promise<HttpResponse>}
 */
export async function rawRequest(
  context: ClientContext,
  input: SendInput
): Promise<HttpResponse> {
  const { url } = input
  await context.service()
  // Uppercase the method and the action, as `grant()` does: the server
  // matches the signed action case-sensitively against the request method,
  // so a lowercase `method: 'put'` or `action: 'put'` would be refused.
  const method = (input.method ?? 'GET').toUpperCase()
  return context.zcapClient.request({
    url,
    capability: input.capability,
    method,
    // Default the capability action to the HTTP method (never `read`/`write`).
    action: (input.action ?? method).toUpperCase(),
    headers: input.headers,
    json: input.json,
    body: input.body
  })
}

/**
 * A plain unsigned `fetch` that maps a network failure to a `PwsError`, the
 * way the rest of the transport does. The response is returned as is,
 * whatever its status: this is the probe primitive for service discovery,
 * which reads the status itself. Everything else sends through
 * `unsignedRequest` or `send()`.
 *
 * @param url {string}
 * @param init {RequestInit}
 * @returns {Promise<Response>}
 */
export async function fetchMapped(
  url: string,
  init: RequestInit
): Promise<Response> {
  try {
    return await fetch(url, init)
  } catch (err) {
    throw mapError(err)
  }
}

/**
 * Sends an **unsigned** request (no capability invocation), for reading public
 * (`PublicCanRead`) resources that need no authorization. Applies the same
 * typed-error mapping and null-on-404 read translation as `send()`. Takes an
 * absolute `url` -- public reads address a resource by its link.
 *
 * Sends through `@interop/http-client`, the same client as `send()`, so the
 * response has the same shape (JSON pre-parsed into `data`) and the same
 * retry and timeout behavior, and `dataOrNull` and `readJsonData` read it
 * exactly as they read a signed one.
 *
 * @param input {object}
 * @param input.url {string}                    absolute URL to read
 * @param [input.method] {string}               HTTP method (defaults to `GET`)
 * @param [input.headers] {Record<string,string>}
 * @param [input.read] {boolean}                when true, a 404/401/403 resolves to `null`
 * @returns {Promise<HttpResponse | null>}
 */
export async function unsignedRequest(input: {
  url: string
  method?: string
  headers?: Record<string, string>
  read?: boolean
}): Promise<HttpResponse | null> {
  try {
    return await httpClient(input.url, {
      method: input.method ?? 'GET',
      headers: input.headers
    })
  } catch (err) {
    // A public read resolves to `null` for any "not readable by you" status,
    // not just 404: a conformant PWS masks unauthorized as 404, but a server
    // that answers a missing capability with 401/403 should honor the same
    // null-if-not-publicly-readable contract rather than throw.
    const status = httpStatus(err)
    if (input.read && (status === 404 || status === 401 || status === 403)) {
      return null
    }
    throw mapError(err)
  }
}

/**
 * Signs and sends a request, applying the typed-error mapping. When `read` is
 * set, a 404 resolves to `null` (MongoDB `findOne` semantics); otherwise every
 * non-2xx maps to a `PwsError` subclass.
 *
 * A request whose URL lies outside the attached capability's invocation target
 * (a Collection Metadata read under a resource-scoped grant, say) is answered
 * here, with nothing sent: the signer would refuse to invoke the capability
 * against it (confused-deputy protection), and the server would mask the
 * unauthorized request as a 404 anyway. So it takes the 404 translations:
 * `null` for a `read` or an `idempotent` delete, `NotFoundError` otherwise.
 * The check is `isValidTarget` from `@interop/zcap`, the rule the server's
 * verifier applies, so the two cannot disagree.
 *
 * @param context {ClientContext}
 * @param input {SendInput}
 * @returns {Promise<HttpResponse | null>}
 */
export async function send(
  context: ClientContext,
  input: SendInput
): Promise<HttpResponse | null> {
  const invocationTarget = input.capability?.invocationTarget
  if (invocationTarget !== undefined) {
    const { url } = input
    if (
      !isValidTarget({
        invocationTarget: url,
        baseInvocationTarget: invocationTarget,
        allowTargetAttenuation: true
      })
    ) {
      if (input.read || input.idempotent) {
        return null
      }
      throw new NotFoundError(
        `"${url}" lies outside the capability's invocation target ` +
          `"${invocationTarget}", which cannot be invoked against it.`,
        { status: 404, requestUrl: url }
      )
    }
  }
  try {
    return await rawRequest(context, input)
  } catch (err) {
    // Only a raw transport error translates: a `PwsError` (such as a discovery
    // refusal) is already an answer and passes through whatever its status.
    if (
      (input.read || input.idempotent) &&
      !(err instanceof PwsError) &&
      httpStatus(err) === 404
    ) {
      return null
    }
    throw mapError(err)
  }
}

/**
 * The `PwsServerError` for a 2xx whose body was not the JSON object the
 * operation required. The request layer parses a body into `data` only for a
 * JSON content type, so naming the content type the server sent points at the
 * cause (a mislabeled or body-less 2xx).
 *
 * @param options {object}
 * @param options.response {HttpResponse | null}
 * @param options.operation {string}   the request, as the message's subject
 * @param options.expected {string}   what the body should have carried
 * @returns {PwsServerError}
 */
export function missingJsonBodyError({
  response,
  operation,
  expected
}: {
  response: HttpResponse | null
  operation: string
  expected: string
}): PwsServerError {
  const contentType = response?.headers.get('content-type') ?? 'no content-type'
  return new PwsServerError(
    `${operation} response carried no JSON body (the server sent ` +
      `${contentType}); expected ${expected}.`
  )
}

/**
 * The GET-a-JSON-description read shared across the handles: a signed
 * null-on-404 `GET` of `url` whose pre-parsed body is unwrapped as `T`. A
 * missing/unauthorized target (404) resolves to `null`. So does a
 * bodyless/non-JSON 2xx (see `dataOrNull`), unless `expected` names what the
 * body should have carried: then that 2xx is a server fault
 * (`PwsServerError`), for a read whose caller must not mistake a misbehaving
 * server for "nothing stored".
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.url {string}           the absolute URL to read
 * @param [options.capability] {IZcap}   capability attached to the request
 * @param [options.expected] {string}    what a 2xx body must carry, for the
 *   error message; absent, a bodyless 2xx reads as `null`
 * @returns {Promise<T | null>}
 */
export async function readData<T>(
  context: ClientContext,
  options: { url: string; capability?: IZcap; expected?: string }
): Promise<T | null> {
  const read = await readDataWithEtag<T>(context, options)
  return read === null ? null : read.data
}

/**
 * {@link readData} keeping the response's `ETag` validator beside the body:
 * the read-with-validator shape a compare-and-swap starts from. `null` on the
 * same conditions as `readData`, and `expected` has the same meaning; `etag`
 * is absent against a server that does not version the target.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.url {string}           the absolute URL to read
 * @param [options.capability] {IZcap}   capability attached to the request
 * @param [options.expected] {string}    see {@link readData}
 * @returns {Promise<{ data: T; etag?: string } | null>}
 */
export async function readDataWithEtag<T>(
  context: ClientContext,
  {
    url,
    capability,
    expected
  }: { url: string; capability?: IZcap; expected?: string }
): Promise<{ data: T; etag?: string } | null> {
  const response = await send(context, {
    url,
    method: 'GET',
    capability,
    read: true
  })
  const data = dataOrNull<T>(response)
  if (data === null) {
    if (response !== null && expected !== undefined) {
      throw missingJsonBodyError({ response, operation: 'Read', expected })
    }
    return null
  }
  return { data, etag: readEtag(response) }
}
