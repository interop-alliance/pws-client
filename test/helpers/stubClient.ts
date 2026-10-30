/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A `WasClient` over a stub `ZcapClient`, for unit tests that drive a handle
 * without a server. The stub hands every `request(...)` call to the test's
 * own handler, which returns a canned `HttpResponse` (see `jsonResponse`) or
 * throws the error the test wants `mapError` to see.
 */
import type { HttpResponse } from '@interop/http-client'
import type { ServiceDescription } from '../../src/index.js'
import { WasClient } from '../../src/index.js'

/**
 * The stub server's origin. The stub lays its URLs out the way the spec does
 * beneath the base server URL: the service description at `/service`, the
 * Spaces Repository at `/spaces/`, and a Space at `/space/{id}/`.
 */
export const STUB_ORIGIN = 'https://was.example'

/**
 * The URL a stubbed `fetch` was called with. The unsigned path sends through
 * `@interop/http-client`, which hands `fetch` a `Request`.
 *
 * @param input {string | Request}
 * @returns {string}
 */
export function requestUrl(input: string | Request): string {
  return typeof input === 'string' ? input : input.url
}

/**
 * The stub server's base server URL (origin plus a trailing slash).
 *
 * @param [origin] {string}   defaults to {@link STUB_ORIGIN}
 * @returns {string}
 */
export function baseServerUrlFor(origin = STUB_ORIGIN): string {
  return `${origin}/`
}

/**
 * The stub server's service description URL, beneath `origin`.
 *
 * @param [origin] {string}   defaults to {@link STUB_ORIGIN}
 * @returns {string}
 */
export function serviceUrlFor(origin = STUB_ORIGIN): string {
  return `${origin}/service`
}

/**
 * The stub server's Spaces Repository URL, beneath `origin`.
 *
 * @param [origin] {string}   defaults to {@link STUB_ORIGIN}
 * @returns {string}
 */
export function spacesUrlFor(origin = STUB_ORIGIN): string {
  return `${origin}/spaces/`
}

/**
 * The URL the stub server names a Space by, in canonical form: what its
 * Create Space `Location` would carry.
 *
 * @param spaceId {string}
 * @param [origin] {string}   defaults to {@link STUB_ORIGIN}
 * @returns {string}
 */
export function spaceUrlFor(spaceId: string, origin = STUB_ORIGIN): string {
  return `${origin}/space/${encodeURIComponent(spaceId)}/`
}

/**
 * A v0.5 service description for a stub server at `origin`, with the Spaces
 * Repository at `spaces/` under it. Passing it to the `WasClient`
 * constructor lets a stubbed client skip network discovery.
 *
 * @param [origin] {string}   defaults to {@link STUB_ORIGIN}
 * @returns {ServiceDescription}
 */
export function serviceDescriptionFor(
  origin = STUB_ORIGIN
): ServiceDescription {
  return {
    url: serviceUrlFor(origin),
    specs: {
      'https://w3id.org/pws': [
        {
          version: '0.5',
          spaces: spacesUrlFor(origin),
          features: ['listing', 'collection-management', 'space-management']
        }
      ]
    }
  }
}

/**
 * The subset of `ZcapClient.request()` arguments the stubs record.
 */
export interface RequestArgs {
  url?: string
  method?: string
  action?: string
  json?: unknown
  body?: unknown
  headers?: Record<string, string>
  capability?: {
    '@context'?: string
    id?: string
    invocationTarget?: string
    controller?: string
  }
}

/**
 * Builds a `WasClient` whose `ZcapClient` answers each request through
 * `request`.
 *
 * @param request {function}   `(args: RequestArgs) => HttpResponse` (may
 *   throw, or return a promise)
 * @returns {WasClient}
 */
export function clientWithStub(
  request: (args: RequestArgs) => HttpResponse | Promise<HttpResponse>
): WasClient {
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    request
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  return new WasClient({
    baseServerUrl: baseServerUrlFor(),
    zcapClient,
    serviceDescription: serviceDescriptionFor()
  })
}

/**
 * A canned response as `@interop/http-client` would pre-parse it: `data` is
 * the JSON body (leave it out for a bodiless 204).
 *
 * @param [options] {object}
 * @param [options.data] {unknown}   the parsed JSON body
 * @param [options.status] {number}   default 200 with a body, 204 without
 * @param [options.headers] {Record<string, string>}
 * @returns {HttpResponse}
 */
export function jsonResponse({
  data,
  status = data === undefined ? 204 : 200,
  headers = {}
}: {
  data?: unknown
  status?: number
  headers?: Record<string, string>
} = {}): HttpResponse {
  return {
    status,
    headers: new Headers(headers),
    data,
    async json() {
      return data
    }
  } as unknown as HttpResponse
}

/**
 * A stubbed `WasClient` that records every request and answers each with the
 * same canned response. `data` is the JSON body (`undefined` for a bodiless
 * reply), `etag` the response `ETag` header (none when left out), and `fail`
 * an HTTP status to throw instead, in the shape `@interop/http-client` rejects
 * with.
 *
 * @param [options] {object}
 * @param [options.data] {unknown}   the response `data` payload
 * @param [options.fail] {number}    an HTTP status to throw instead
 * @param [options.etag] {string}    the response `ETag` header, if any
 * @returns {object} { client, calls, lastRequest }
 */
export function clientWithRequestSpy({
  data,
  fail,
  etag
}: { data?: unknown; fail?: number; etag?: string } = {}): {
  client: WasClient
  calls: RequestArgs[]
  lastRequest: () => RequestArgs | undefined
} {
  const calls: RequestArgs[] = []
  const client = clientWithStub(args => {
    calls.push(args)
    if (fail !== undefined) {
      throw { status: fail, response: { status: fail } }
    }
    return jsonResponse({
      data,
      status: 200,
      headers: etag === undefined ? {} : { etag }
    })
  })
  return { client, calls, lastRequest: () => calls.at(-1) }
}
