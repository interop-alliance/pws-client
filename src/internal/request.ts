/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The load-bearing transport layer: wraps `zcapClient.request(...)` on an
 * absolute URL, defaulting the capability `action` to the one the HTTP method
 * is authorized under (see `actionForMethod`), not ezcap's `read`/`write`.
 * `send()` adds the typed-error
 * mapping and the null-on-404 read translation; `rawRequest()` is the
 * unmapped escape hatch used by `pws.request()`. Every signed request first
 * awaits the context's memoized service discovery, so no request reaches a
 * server whose protocol version this client does not speak.
 */
import { checkDereferencedTarget, type ZcapClient } from '@interop/ezcap'
import { isValidTarget } from '@interop/zcap'
import { httpClient, type HttpResponse } from '@interop/http-client'
import {
  NotFoundError,
  PwsError,
  PwsServerError,
  TargetDereferenceError,
  errorMessage,
  httpStatus
} from '../errors.js'
import { mapError } from './mapError.js'
import { dataOrNull } from './content.js'
import { readEtag } from './conditional.js'
import { findChainRootTarget } from './rootCapability.js'
import type { EncryptionProvider } from '../codec.js'
import type {
  DereferenceTarget,
  IZcap,
  RequestInput,
  ServiceInfo
} from '../types.js'

/**
 * The shared context threaded through every handle: the wrapped ezcap client,
 * the controller DID of its signer, the optional encryption provider that
 * supplies an encrypting codec for the collections the client holds keys
 * for, the memoized service discovery every signed request waits on, and the
 * hook that dereferences a DID URL. It is called only for a DID URL, by
 * `dereferencedTarget` here and by ezcap under `pws.request()`. That covers
 * a capability's target, a DID URL a caller addresses directly, and
 * `openedOn` before each request of a handle that carries it.
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
  /**
   * What service discovery learned about the server that answers `url`. That
   * is `service()` for a URL on the client's own server. A URL on another
   * server is discovered from the URL itself, with two unsigned requests,
   * and the result is memoized per URL.
   */
  serviceAt: (url: string) => Promise<ServiceInfo>
  dereferenceTarget: DereferenceTarget
  /**
   * The root DID URL of the Space and the Space URL it dereferenced to, on
   * the context of a handle opened with `fromDidUrl()` and of the handles
   * beneath it. `send()` dereferences `didUrl` before every request and
   * compares the result with `spaceUrl` (see `checkOpenedLocation`). The
   * client's own context carries none.
   */
  openedOn?: { didUrl: string; spaceUrl: string }
}

/**
 * The context of a handle opened on a DID URL: `context` plus `openedOn`.
 * The result inherits from `context` and is not a copy of it, since a copy
 * would read the lazy `controllerDid` getter.
 *
 * @param context {ClientContext}   the client's context
 * @param openedOn {object}   the Space's root DID URL and its Space URL
 * @returns {ClientContext}
 */
export function contextOpenedOn(
  context: ClientContext,
  openedOn: NonNullable<ClientContext['openedOn']>
): ClientContext {
  return Object.create(context, {
    openedOn: { value: openedOn, enumerable: true }
  }) as ClientContext
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
 * The capability action an HTTP method is authorized under. The PWS action
 * vocabulary is `GET`, `POST`, `PUT` and `DELETE`. A `HEAD` request is
 * authorized as a `GET`, so its invocation names `GET`. Every other method
 * names itself. `method` is expected in uppercase.
 *
 * @param method {string}   the uppercase HTTP method
 * @returns {string}
 */
export function actionForMethod(method: string): string {
  return method === 'HEAD' ? 'GET' : method
}

/**
 * The https URL a capability's invocation target names. An https target is
 * returned as it is, with no call to the hook. A DID URL target goes through
 * the context's `dereferenceTarget` hook, and the result passes the check
 * ezcap applies to it at signing. A DID URL a caller addresses directly
 * (`pws.request()`, `fromDidUrl()`) is mapped the same way.
 *
 * @param context {ClientContext}
 * @param invocationTarget {string}   the capability's `invocationTarget`, or
 *   another URL to map
 * @returns {Promise<string>}
 * @throws {TargetDereferenceError}   when the hook fails, or its result is
 *   not a URL a request can be sent to
 */
export async function dereferencedTarget(
  context: ClientContext,
  invocationTarget: string
): Promise<string> {
  if (!invocationTarget.startsWith('did:')) {
    return invocationTarget
  }
  try {
    const url = await context.dereferenceTarget({ invocationTarget })
    checkDereferencedTarget({ dereferencedTarget: url })
    return url
  } catch (err) {
    // Any other error of a caller's hook is wrapped, a `PwsError` included:
    // one with a 404 status would read as an absent resource.
    if (err instanceof TargetDereferenceError) {
      throw err
    }
    throw new TargetDereferenceError(
      `The DID URL "${invocationTarget}" could not be dereferenced: ` +
        errorMessage(err),
      { cause: err }
    )
  }
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
 * @param [dereferenceTarget] {DereferenceTarget}   the hook handed to ezcap.
 *   Defaults to the context's. `send()` passes one that returns the URL it
 *   has already dereferenced, so ezcap does not call the hook again. A
 *   request `send()` answers without sending may call it once more, for the
 *   chain's root (see `checkRootLocation`)
 * @returns {Promise<HttpResponse>}
 */
export async function rawRequest(
  context: ClientContext,
  input: SendInput,
  dereferenceTarget: DereferenceTarget = context.dereferenceTarget
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
    // Default the capability action to the one the method is authorized
    // under. ezcap's own default is the method itself, which would sign a
    // `HEAD` request as `HEAD`. An explicit `action` is signed as given.
    action: (input.action ?? actionForMethod(method)).toUpperCase(),
    headers: input.headers,
    json: input.json,
    body: input.body,
    dereferenceTarget
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
 * Rejects a request that does not fit the location a DID URL chain is rooted
 * at today. Every URL of a handle lies under its Space URL, so a request URL
 * outside the root's current URL comes from a handle that addresses another
 * location. A handle built before the Space moved is the usual case. Such a
 * request must not take the 404 translations, which would report the
 * documents as absent. A chain rooted at an https URL is not checked.
 *
 * The target and the root are dereferenced by separate calls of the hook, so
 * one answer can be older than the other. A DID URL target that dereferences
 * outside the root's URL is refused too. That covers a root answer older than
 * a move, and a target the DID document maps to another Space.
 *
 * The cause cannot be told from the request alone. A handle built with
 * `spaceAt()` for a Space the chain is not rooted in is refused the same way.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.url {string}   the request URL
 * @param options.capability {IZcap}   the capability attached to the request
 * @param options.targetUrl {string}   the URL the capability's target
 *   dereferences to. A grant on the Space names its root as its target, so
 *   the root is not dereferenced a second time
 * @returns {Promise<void>}
 * @throws {TargetDereferenceError}   when `url` or `targetUrl` is not at or
 *   beneath the URL the root's DID URL dereferences to, or that DID URL
 *   cannot be dereferenced
 */
export async function checkRootLocation(
  context: ClientContext,
  {
    url,
    capability,
    targetUrl
  }: { url: string; capability: IZcap; targetUrl: string }
): Promise<void> {
  const root = findChainRootTarget(capability)
  if (!root?.startsWith('did:')) {
    return
  }
  const { invocationTarget } = capability
  const rootUrl =
    root === invocationTarget
      ? targetUrl
      : await dereferencedTarget(context, root)
  const advice =
    'The request was not sent. If the Space has moved, call ' +
    '`fromCapability()` again for a handle at its current location.'
  if (
    !isValidTarget({
      invocationTarget: url,
      baseInvocationTarget: rootUrl,
      allowTargetAttenuation: true
    })
  ) {
    throw new TargetDereferenceError(
      `"${url}" is not at or beneath "${rootUrl}", the URL the capability's ` +
        `root "${root}" dereferences to now. The handle addresses another ` +
        `location. ${advice}`,
      { requestUrl: url }
    )
  }
  if (
    invocationTarget.startsWith('did:') &&
    !isValidTarget({
      invocationTarget: targetUrl,
      baseInvocationTarget: rootUrl,
      allowTargetAttenuation: true
    })
  ) {
    throw new TargetDereferenceError(
      `The capability's target "${invocationTarget}" dereferences to ` +
        `"${targetUrl}", which is not at or beneath "${rootUrl}", the URL ` +
        `its root "${root}" dereferences to. ${advice}`,
      { requestUrl: url }
    )
  }
}

/**
 * Rejects a request from a handle opened on a DID URL once that handle no
 * longer addresses the Space. The handle keeps the https URLs it resolved
 * when it was built. So the Space's root DID URL is dereferenced again, and
 * the request is refused when the result is no longer the handle's Space
 * URL. Sent to the old location, a read would resolve `null` and an
 * idempotent delete would report success.
 *
 * Every URL of the handle lies under its Space URL, so the two Space URLs
 * are compared and the request URL is not parsed.
 *
 * @param context {ClientContext}
 * @param url {string}   the request URL, for the error
 * @param openedOn {object}   the context's `openedOn`
 * @returns {Promise<void>}
 * @throws {TargetDereferenceError}   when the root DID URL dereferences to
 *   another URL now, or cannot be dereferenced
 */
async function checkOpenedLocation(
  context: ClientContext,
  url: string,
  { didUrl, spaceUrl }: NonNullable<ClientContext['openedOn']>
): Promise<void> {
  const rootUrl = await dereferencedTarget(context, didUrl)
  if (rootUrl !== spaceUrl) {
    throw new TargetDereferenceError(
      `The Space's DID URL "${didUrl}" dereferences to "${rootUrl}" now, ` +
        `and this handle addresses "${spaceUrl}". The request was not ` +
        'sent. If the Space has moved, call `fromDidUrl()` again for a ' +
        'handle at its current location.',
      { requestUrl: url }
    )
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
 * A DID URL target is dereferenced first, and the request URL is compared
 * with the https URL it names. A target that cannot be dereferenced rejects
 * with `TargetDereferenceError`, whatever the 404 translations.
 *
 * For a chain rooted at a DID URL, a request outside the target also goes
 * through `checkRootLocation`. It rejects with `TargetDereferenceError`,
 * instead of taking the 404 translations, when the request URL or the
 * dereferenced target lies outside the URL the root dereferences to. A handle
 * built before the Space moved is refused this way.
 *
 * A handle opened with `fromDidUrl()` is checked before anything else, on
 * every request (see `checkOpenedLocation`).
 *
 * @param context {ClientContext}
 * @param input {SendInput}
 * @returns {Promise<HttpResponse | null>}
 */
export async function send(
  context: ClientContext,
  input: SendInput
): Promise<HttpResponse | null> {
  const { capability } = input
  if (context.openedOn !== undefined) {
    await checkOpenedLocation(context, input.url, context.openedOn)
  }
  let baseInvocationTarget: string | undefined
  // A capability with no target (a stand-in a caller passes through) is left
  // for the signer to judge.
  const invocationTarget = capability?.invocationTarget
  if (capability !== undefined && invocationTarget !== undefined) {
    const { url } = input
    baseInvocationTarget = await dereferencedTarget(context, invocationTarget)
    if (
      !isValidTarget({
        invocationTarget: url,
        baseInvocationTarget,
        allowTargetAttenuation: true
      })
    ) {
      await checkRootLocation(context, {
        url,
        capability,
        targetUrl: baseInvocationTarget
      })
      if (input.read || input.idempotent) {
        return null
      }
      throw new NotFoundError(
        `"${url}" lies outside the capability's invocation target ` +
          `"${invocationTarget}"` +
          (baseInvocationTarget === invocationTarget
            ? ''
            : ` (dereferenced to "${baseInvocationTarget}")`) +
          ', which cannot be invoked against it.',
        { status: 404, requestUrl: url }
      )
    }
  }
  try {
    // ezcap signs against the URL the check above used, so the two agree and
    // the hook is not called a second time.
    const resolved = baseInvocationTarget
    return await rawRequest(
      context,
      input,
      resolved === undefined ? undefined : async () => resolved
    )
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
