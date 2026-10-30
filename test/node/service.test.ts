/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for service discovery: the `rel="service"` Link header parser,
 * version selection against fixture service descriptions, the two ways to
 * open a client (`baseServerUrl`, `PwsClient.forSpace`), the consistency
 * check of a description against the base, and `PwsClient.service()` with
 * the gate every signed request passes through. A stubbed global `fetch`
 * serves the discovery requests and a stub `ZcapClient` records signed ones,
 * so no server is involved.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'

import type { HttpResponse } from '@interop/http-client'

import {
  IncompatibleServerError,
  NotSupportedError,
  ValidationError,
  PwsClient,
  PwsServerError,
  readServiceDescription as readServiceDescriptionFromIndex
} from '../../src/index.js'
import type { ServiceDescription } from '../../src/index.js'
import {
  PWS_SPEC_ID,
  readServiceDescription,
  selectServiceVersion,
  serviceLinkTarget
} from '../../src/internal/service.js'
import type { RequestArgs } from '../helpers/stubClient.js'
import { jsonResponse, requestUrl } from '../helpers/stubClient.js'

const SPACES_URL = 'https://host.example/pws/spaces/'
const BASE_URL = 'https://host.example/pws/'
const SERVICE_URL = 'https://host.example/pws/service'
const ALICE_URL = 'https://alice.example/'

/**
 * A service description in the shape of the spec's example: a v0.5 and a v0.4
 * entry for PWS, another specification, and an `instance` disclosure.
 *
 * @returns {ServiceDescription}
 */
function exampleDescription(): ServiceDescription {
  return {
    url: SERVICE_URL,
    specs: {
      [PWS_SPEC_ID]: [
        {
          version: '0.5',
          url: 'https://w3c-ccg.github.io/portable-web-spaces-spec/v0.5/',
          spaces: 'https://host.example/pws/spaces/',
          features: ['listing', 'collection-management', 'future-token'],
          signatureAlgorithms: ['EdDSA'],
          zcapCryptosuites: ['eddsa-jcs-2022']
        },
        {
          version: '0.4',
          spaces: 'https://host.example/pws/spaces/',
          features: ['listing']
        }
      ],
      'https://w3id.org/encrypted-collections': [{ version: '0.2' }]
    },
    instance: { name: 'web-spaces-server' }
  }
}

describe('serviceLinkTarget', () => {
  it('reads the service target from a single link', () => {
    expect(
      serviceLinkTarget({
        header: `<${SERVICE_URL}>; rel="service"`,
        baseUrl: SPACES_URL
      })
    ).toBe(SERVICE_URL)
  })

  it('finds the service link among others, with commas in quoted params', () => {
    const header =
      '<https://host.example/a>; rel="next"; title="a, b", ' +
      `<${SERVICE_URL}>; rel=service`
    expect(serviceLinkTarget({ header, baseUrl: SPACES_URL })).toBe(SERVICE_URL)
  })

  it('matches one of several relation types, case-insensitively', () => {
    expect(
      serviceLinkTarget({
        header: `<${SERVICE_URL}>; rel="describedby SERVICE"`,
        baseUrl: SPACES_URL
      })
    ).toBe(SERVICE_URL)
  })

  it('resolves a relative target against the response URL', () => {
    expect(
      serviceLinkTarget({
        header: '<service>; rel="service"',
        baseUrl: 'https://host.example/pws/space/s/c/r'
      })
    ).toBe('https://host.example/pws/space/s/c/service')
  })

  it('answers undefined with no header or no service link', () => {
    expect(serviceLinkTarget({ header: null, baseUrl: SPACES_URL })).toBe(
      undefined
    )
    expect(
      serviceLinkTarget({
        header: '<https://host.example/a>; rel="service-desc"',
        baseUrl: SPACES_URL
      })
    ).toBe(undefined)
  })
})

describe('selectServiceVersion', () => {
  it('chooses the v0.5 entry and exposes its spaces URL and features', () => {
    const info = selectServiceVersion(exampleDescription())
    expect(info.version).toBe('0.5')
    expect(info.entry.version).toBe('0.5')
    expect(info.spacesUrl).toBe('https://host.example/pws/spaces/')
    expect(info.features).toEqual([
      'listing',
      'collection-management',
      'future-token'
    ])
    expect(info.description.url).toBe(SERVICE_URL)
  })

  it('carries unknown feature tokens and reads an absent token as unsupported', () => {
    const info = selectServiceVersion(exampleDescription())
    expect(info.hasFeature('future-token')).toBe(true)
    expect(info.hasFeature('collection-management')).toBe(true)
    expect(info.hasFeature('quotas')).toBe(false)
  })

  it('reads an absent features array as no features', () => {
    const info = selectServiceVersion({
      url: SERVICE_URL,
      specs: { [PWS_SPEC_ID]: [{ version: '0.5' }] }
    })
    expect(info.features).toEqual([])
    expect(info.hasFeature('listing')).toBe(false)
  })

  it('canonicalizes a spaces URL advertised without its trailing slash', () => {
    const info = selectServiceVersion({
      url: SERVICE_URL,
      specs: {
        [PWS_SPEC_ID]: [
          { version: '0.5', spaces: 'https://host.example/pws/spaces' }
        ]
      }
    })
    expect(info.spacesUrl).toBe('https://host.example/pws/spaces/')
  })

  it('leaves spacesUrl absent when the entry has no spaces member', () => {
    const info = selectServiceVersion({
      url: SERVICE_URL,
      specs: { [PWS_SPEC_ID]: [{ version: '0.5', features: ['listing'] }] }
    })
    expect(info.spacesUrl).toBe(undefined)
    expect('spacesUrl' in info).toBe(false)
  })

  it('ignores an entry without a version', () => {
    const info = selectServiceVersion({
      url: SERVICE_URL,
      specs: {
        [PWS_SPEC_ID]: [
          { spaces: 'https://evil.example/spaces/' },
          { version: '0.5', spaces: 'https://host.example/pws/spaces/' }
        ]
      }
    })
    expect(info.spacesUrl).toBe('https://host.example/pws/spaces/')
  })

  it('ignores unknown specs keys, including near-miss identifiers', () => {
    const attempt = (): unknown =>
      selectServiceVersion({
        url: SERVICE_URL,
        specs: {
          'https://w3id.org/pws/': [{ version: '0.5' }],
          'http://w3id.org/pws': [{ version: '0.5' }],
          'https://example.com/other-spec': [{ version: '0.5' }]
        }
      })
    expect(attempt).toThrow(IncompatibleServerError)
  })

  it('refuses a server that lists only versions this client does not speak', () => {
    const attempt = (): unknown =>
      selectServiceVersion({
        url: SERVICE_URL,
        specs: { [PWS_SPEC_ID]: [{ version: '0.4' }, { version: '1.0' }] }
      })
    expect(attempt).toThrow(IncompatibleServerError)
    expect(attempt).toThrow(/offered: 0\.4, 1\.0/)
  })

  it.each([
    ['a non-object', 'nope'],
    ['null', null],
    ['a document without url', { specs: { [PWS_SPEC_ID]: [] } }],
    ['a document without specs', { url: SERVICE_URL }],
    ['an array specs', { url: SERVICE_URL, specs: [] }],
    [
      'a non-array version list',
      { url: SERVICE_URL, specs: { [PWS_SPEC_ID]: { version: '0.5' } } }
    ],
    [
      'a relative spaces URL',
      {
        url: SERVICE_URL,
        specs: { [PWS_SPEC_ID]: [{ version: '0.5', spaces: '/spaces/' }] }
      }
    ],
    [
      'a non-array features member',
      {
        url: SERVICE_URL,
        specs: { [PWS_SPEC_ID]: [{ version: '0.5', features: 'listing' }] }
      }
    ]
  ])('refuses %s with IncompatibleServerError', (_label, description) => {
    expect(() => selectServiceVersion(description)).toThrow(
      IncompatibleServerError
    )
  })

  it('does not look at instance', () => {
    const description = exampleDescription()
    const withOddInstance = {
      ...description,
      instance: { name: 42, version: ['x'] }
    }
    expect(selectServiceVersion(withOddInstance).version).toBe('0.5')
    const withoutInstance = { url: description.url, specs: description.specs }
    expect(selectServiceVersion(withoutInstance).version).toBe('0.5')
  })
})

/**
 * One request the stubbed global `fetch` saw.
 */
interface FetchCall {
  url: string
  method: string
  headers: Record<string, string>
}

/**
 * Stubs the global `fetch`: a `HEAD` of any URL answers the probe (a status
 * and an optional `Link` header), and a `GET` of the service URL answers the
 * service description `body`.
 *
 * @param options {object}
 * @param [options.probeStatus] {number}   the `HEAD` status, default 404
 * @param [options.link] {string | null}   the `Link` header, `null` for none
 * @param [options.body] {string}   the service description response body
 * @param [options.serviceStatus] {number}   the service `GET` status
 * @returns {FetchCall[]}   the recorded calls
 */
function stubDiscovery({
  probeStatus = 404,
  link = `<${SERVICE_URL}>; rel="service"`,
  body = JSON.stringify(exampleDescription()),
  serviceStatus = 200
}: {
  probeStatus?: number
  link?: string | null
  body?: string
  serviceStatus?: number
} = {}): FetchCall[] {
  const calls: FetchCall[] = []
  vi.stubGlobal('fetch', async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET'
    calls.push({
      url,
      method,
      headers: (init.headers ?? {}) as Record<string, string>
    })
    if (method === 'HEAD') {
      return new Response(null, {
        status: probeStatus,
        headers: link === null ? {} : { link }
      })
    }
    if (url === SERVICE_URL) {
      return new Response(body, {
        status: serviceStatus,
        headers: { 'content-type': 'application/json' }
      })
    }
    throw new Error(`unexpected fetch ${method} ${url}`)
  })
  return calls
}

/**
 * A stub `ZcapClient` that records signed requests and answers each with
 * `data`.
 *
 * @param [data] {unknown}   the signed response body
 * @returns {{ zcapClient: ZcapClientType, signed: RequestArgs[] }}
 */
function stubZcapClient(data: unknown = { id: 'new-space' }): {
  zcapClient: ZcapClientType
  signed: RequestArgs[]
} {
  const signed: RequestArgs[] = []
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request(args: RequestArgs): Promise<HttpResponse> {
      signed.push(args)
      return jsonResponse({
        data,
        status: 201,
        headers: { location: 'https://host.example/pws/space/new-space/' }
      })
    }
  } as unknown as ZcapClientType
  return { zcapClient, signed }
}

type ZcapClientType = ConstructorParameters<typeof PwsClient>[0]['zcapClient']

/**
 * Builds a `PwsClient` over a stub `ZcapClient`, from {@link BASE_URL}.
 *
 * @param [options] {object}
 * @param [options.data] {unknown}   the signed response body
 * @param [options.serviceDescription] {ServiceDescription}
 * @returns {{ pws: PwsClient, signed: RequestArgs[] }}
 */
function client({
  data,
  serviceDescription
}: {
  data?: unknown
  serviceDescription?: ServiceDescription
} = {}): {
  pws: PwsClient
  signed: RequestArgs[]
} {
  const { zcapClient, signed } = stubZcapClient(data)
  const pws = new PwsClient({
    baseServerUrl: BASE_URL,
    zcapClient,
    serviceDescription
  })
  return { pws, signed }
}

/**
 * Builds a `PwsClient` fixed on the Space at `spaceUrl`.
 *
 * @param [options] {object}
 * @param [options.spaceUrl] {string}   defaults to {@link ALICE_URL}
 * @param [options.serviceDescription] {ServiceDescription}
 * @returns {{ pws: PwsClient, signed: RequestArgs[] }}
 */
function spaceClient({
  spaceUrl = ALICE_URL,
  serviceDescription
}: {
  spaceUrl?: string
  serviceDescription?: ServiceDescription
} = {}): { pws: PwsClient; signed: RequestArgs[] } {
  const { zcapClient, signed } = stubZcapClient()
  const pws = PwsClient.forSpace({ spaceUrl, zcapClient, serviceDescription })
  return { pws, signed }
}

/**
 * The fixture description with its `url` and `spaces` members replaced.
 *
 * @param [options] {object}
 * @param [options.url] {string}
 * @param [options.spaces] {string | null}   `null` omits the member
 * @returns {ServiceDescription}
 */
function descriptionWith({
  url = SERVICE_URL,
  spaces = SPACES_URL
}: { url?: string; spaces?: string | null } = {}): ServiceDescription {
  return {
    url,
    specs: {
      [PWS_SPEC_ID]: [
        spaces === null ? { version: '0.5' } : { version: '0.5', spaces }
      ]
    }
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('readServiceDescription', () => {
  it('reads the document with one unsigned GET and selects a version', async () => {
    const calls = stubDiscovery()
    const info = await readServiceDescription({ serviceUrl: SERVICE_URL })
    expect(info.version).toBe('0.5')
    expect(info.spacesUrl).toBe(SPACES_URL)
    expect(calls.map(call => `${call.method} ${call.url}`)).toEqual([
      `GET ${SERVICE_URL}`
    ])
  })

  it('is exported from the core entry', () => {
    expect(readServiceDescriptionFromIndex).toBe(readServiceDescription)
  })
})

describe('PwsClient.service() from a base server URL', () => {
  it('GETs {base}service unsigned, with no HEAD probe', async () => {
    const calls = stubDiscovery()
    const { pws, signed } = client()
    const info = await pws.service()
    expect(info.version).toBe('0.5')
    expect(info.spacesUrl).toBe(SPACES_URL)
    expect(calls.map(call => `${call.method} ${call.url}`)).toEqual([
      `GET ${SERVICE_URL}`
    ])
    const headerNames = calls.flatMap(call =>
      Object.keys(call.headers).map(name => name.toLowerCase())
    )
    expect(headerNames).not.toContain('authorization')
    expect(headerNames).not.toContain('capability-invocation')
    expect(signed).toEqual([])
  })

  it('memoizes discovery across calls and signed requests', async () => {
    const calls = stubDiscovery()
    const { pws } = client()
    await Promise.all([pws.service(), pws.service()])
    await pws.spaceAt('https://host.example/pws/space/s/').describe()
    expect(calls).toHaveLength(1)
  })

  it('discovers again on refresh', async () => {
    const calls = stubDiscovery()
    const { pws } = client()
    await pws.service()
    await pws.service({ refresh: true })
    expect(calls).toHaveLength(2)
  })

  it('refuses a service description that is not JSON', async () => {
    stubDiscovery({ body: '<html>' })
    await expect(client().pws.service()).rejects.toThrow(
      IncompatibleServerError
    )
  })

  it('refuses a service URL that answers 404 or 501', async () => {
    for (const serviceStatus of [404, 501]) {
      stubDiscovery({ serviceStatus, body: '' })
      await expect(client().pws.service()).rejects.toThrow(
        IncompatibleServerError
      )
    }
  })

  it('reports a transient service URL failure as one, and retries', async () => {
    stubDiscovery({ serviceStatus: 503, body: '' })
    const { pws } = client()
    const failure = pws.service()
    await expect(failure).rejects.toThrow(PwsServerError)
    await expect(failure).rejects.not.toThrow(IncompatibleServerError)
    stubDiscovery()
    expect((await pws.service()).version).toBe('0.5')
  })
})

describe('the description is checked against the base', () => {
  it('passes a description that agrees with the base', async () => {
    stubDiscovery()
    expect((await client().pws.service()).version).toBe('0.5')
    const calls = stubDiscovery()
    const { pws } = client({ serviceDescription: descriptionWith() })
    expect((await pws.service()).version).toBe('0.5')
    expect(calls).toEqual([])
  })

  it('refuses a description whose url differs, naming both URLs', async () => {
    const other = descriptionWith({ url: 'https://other.example/service' })
    const failure = client({ serviceDescription: other }).pws.service()
    await expect(failure).rejects.toThrow(IncompatibleServerError)
    await expect(failure).rejects.toThrow('https://other.example/service')
    await expect(failure).rejects.toThrow(SERVICE_URL)
  })

  it('refuses a description fetched from the base that names another url', async () => {
    stubDiscovery({
      body: JSON.stringify(descriptionWith({ url: 'https://other.example/s' }))
    })
    await expect(client().pws.service()).rejects.toThrow(
      IncompatibleServerError
    )
  })

  it('refuses a description whose spaces differs, naming both URLs', async () => {
    const other = descriptionWith({
      spaces: 'https://host.example/else/spaces/'
    })
    const failure = client({ serviceDescription: other }).pws.service()
    await expect(failure).rejects.toThrow(IncompatibleServerError)
    await expect(failure).rejects.toThrow('https://host.example/else/spaces/')
    await expect(failure).rejects.toThrow(SPACES_URL)
  })

  it('accepts a spaces URL advertised without its trailing slash', async () => {
    const slashless = descriptionWith({
      spaces: 'https://host.example/pws/spaces'
    })
    const { pws } = client({ serviceDescription: slashless })
    expect((await pws.service()).spacesUrl).toBe(SPACES_URL)
  })

  it('passes a description with no spaces, then refuses createSpace and listSpaces', async () => {
    const { pws, signed } = client({
      serviceDescription: descriptionWith({ spaces: null })
    })
    expect((await pws.service()).spacesUrl).toBeUndefined()
    await expect(pws.createSpace()).rejects.toThrow(NotSupportedError)
    await expect(pws.listSpaces()).rejects.toThrow(
      `The server at "${SERVICE_URL}" does not implement the Spaces Repository`
    )
    expect(signed).toEqual([])
  })

  it('refuses a cached description with no understood version', async () => {
    const calls = stubDiscovery()
    const { pws } = client({
      serviceDescription: {
        url: SERVICE_URL,
        specs: { [PWS_SPEC_ID]: [{ version: '0.4' }] }
      }
    })
    await expect(pws.service()).rejects.toThrow(IncompatibleServerError)
    expect(calls).toEqual([])
  })

  it('accepts a cached description whose url serializes to {base}service', async () => {
    const { pws } = client({
      serviceDescription: descriptionWith({
        url: 'https://HOST.example:443/pws/service'
      })
    })
    expect((await pws.service()).version).toBe('0.5')
  })
})

describe('PwsClient.forSpace()', () => {
  it('HEADs the Space URL, follows the service link, and GETs it unsigned', async () => {
    const calls = stubDiscovery()
    const { pws, signed } = spaceClient()
    const info = await pws.service()
    expect(info.version).toBe('0.5')
    expect(calls.map(call => `${call.method} ${call.url}`)).toEqual([
      `HEAD ${ALICE_URL}`,
      `GET ${SERVICE_URL}`
    ])
    const headerNames = calls.flatMap(call =>
      Object.keys(call.headers).map(name => name.toLowerCase())
    )
    expect(headerNames).not.toContain('authorization')
    expect(signed).toEqual([])
  })

  it('does not check the description against any base', async () => {
    const calls = stubDiscovery({
      body: JSON.stringify(
        descriptionWith({
          url: 'https://elsewhere.example/service',
          spaces: 'https://elsewhere.example/spaces/'
        })
      )
    })
    const info = await spaceClient().pws.service()
    expect(info.version).toBe('0.5')
    expect(calls).toHaveLength(2)
    const cached = spaceClient({
      serviceDescription: descriptionWith({
        url: 'https://elsewhere.example/s'
      })
    })
    expect((await cached.pws.service()).version).toBe('0.5')
  })

  it('exposes spaceUrl and no baseServerUrl', () => {
    const { pws } = spaceClient({ spaceUrl: 'https://ALICE.example:443' })
    expect(pws.spaceUrl).toBe(ALICE_URL)
    expect(pws.baseServerUrl).toBeUndefined()
  })

  it('opens the fixed Space and its Collections at the origin', () => {
    const { pws } = spaceClient()
    expect(pws.spaceAt(pws.spaceUrl!).collection('posts').url).toBe(
      'https://alice.example/posts/'
    )
  })

  it('throws NotSupportedError from space(id), createSpace() and listSpaces()', async () => {
    const { pws, signed } = spaceClient()
    expect(() => pws.space('s')).toThrow(NotSupportedError)
    await expect(pws.createSpace()).rejects.toThrow(NotSupportedError)
    await expect(pws.listSpaces()).rejects.toThrow(NotSupportedError)
    expect(signed).toEqual([])
  })

  it('refuses both a zcapClient and a signer, or neither', () => {
    const { zcapClient } = stubZcapClient()
    expect(() =>
      PwsClient.forSpace({
        spaceUrl: ALICE_URL,
        zcapClient,
        signer: {} as never
      } as unknown as Parameters<typeof PwsClient.forSpace>[0])
    ).toThrow(ValidationError)
    expect(() =>
      PwsClient.forSpace({ spaceUrl: ALICE_URL } as unknown as Parameters<
        typeof PwsClient.forSpace
      >[0])
    ).toThrow(ValidationError)
  })

  it('refuses a spaceUrl that is not an http(s) URL', () => {
    const { zcapClient } = stubZcapClient()
    for (const spaceUrl of ['ftp://alice.example/', 'not a url', '/space/s/']) {
      expect(() => PwsClient.forSpace({ spaceUrl, zcapClient })).toThrow(
        ValidationError
      )
    }
  })
})

describe('PwsClient.service() on a client fixed on a Space (forSpace)', () => {
  it('reads the link from a 308 or any other probe status', async () => {
    stubDiscovery({ probeStatus: 308 })
    expect((await spaceClient().pws.service()).version).toBe('0.5')
  })

  it('memoizes the probe and the read together', async () => {
    const calls = stubDiscovery()
    const { pws } = spaceClient()
    await Promise.all([pws.service(), pws.service()])
    expect(calls).toHaveLength(2)
    await pws.service({ refresh: true })
    expect(calls).toHaveLength(4)
  })

  it('refuses a server whose response has no service link (pre-0.5)', async () => {
    stubDiscovery({ link: null })
    await expect(spaceClient().pws.service()).rejects.toThrow(
      IncompatibleServerError
    )
  })

  it('refuses a service link whose target answers 404', async () => {
    stubDiscovery({ serviceStatus: 404, body: '' })
    await expect(spaceClient().pws.service()).rejects.toThrow(
      IncompatibleServerError
    )
  })

  it('reports a server fault without the link as transient, and retries', async () => {
    stubDiscovery({ probeStatus: 503, link: null })
    const { pws } = spaceClient()
    const failure = pws.service()
    await expect(failure).rejects.toThrow(PwsServerError)
    await expect(failure).rejects.not.toThrow(IncompatibleServerError)
    stubDiscovery()
    expect((await pws.service()).version).toBe('0.5')
  })

  it.each([501, 505, 507])(
    'refuses a %i probe without the link as incompatible, with no status',
    async probeStatus => {
      stubDiscovery({ probeStatus, link: null })
      const failure = spaceClient().pws.service()
      await expect(failure).rejects.toThrow(IncompatibleServerError)
      await expect(failure).rejects.toMatchObject({ status: undefined })
    }
  )
})

describe('PwsClient construction', () => {
  const { zcapClient } = stubZcapClient()

  it('exposes baseServerUrl in canonical form', () => {
    expect(
      new PwsClient({ baseServerUrl: BASE_URL, zcapClient })
    ).toMatchObject({ baseServerUrl: BASE_URL })
    expect(
      new PwsClient({ baseServerUrl: 'https://h/pws', zcapClient })
        .baseServerUrl
    ).toBe('https://h/pws/')
    expect(
      new PwsClient({ baseServerUrl: 'https://HOST.example:443', zcapClient })
        .baseServerUrl
    ).toBe('https://host.example/')
    expect(
      new PwsClient({ baseServerUrl: BASE_URL, zcapClient }).spaceUrl
    ).toBeUndefined()
  })

  it('refuses a base that is not an absolute http(s) URL without query or fragment', () => {
    for (const baseServerUrl of [
      'not a url',
      '/pws/',
      'ftp://h/pws/',
      'file:///pws/',
      'https://h/pws/?q=1',
      'https://h/pws/#frag'
    ]) {
      expect(() => new PwsClient({ baseServerUrl, zcapClient })).toThrow(
        ValidationError
      )
      expect(() =>
        PwsClient.fromSigner({ baseServerUrl, signer: {} as never })
      ).toThrow(ValidationError)
    }
  })
})

describe('the discovery gate on signed requests', () => {
  it('stops a signed read before signing, instead of resolving to null', async () => {
    stubDiscovery({ serviceStatus: 404, body: '' })
    const { pws, signed } = client()
    await expect(
      pws.spaceAt('https://host.example/pws/space/s/').describe()
    ).rejects.toThrow(IncompatibleServerError)
    await expect(
      pws.request({ url: 'https://host.example/pws/space/s/' })
    ).rejects.toThrow(IncompatibleServerError)
    expect(signed).toEqual([])
  })

  it('does not gate unsigned public reads', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', async (input: string | Request) => {
      calls.push(requestUrl(input))
      return new Response(JSON.stringify({ hello: 'world' }), {
        headers: { 'content-type': 'application/json' }
      })
    })
    const { pws } = client()
    await pws.publicRead({ resourceUrl: 'https://other.example/space/s/c/r' })
    expect(calls).toEqual(['https://other.example/space/s/c/r'])
  })
})

describe('the Spaces Repository URL', () => {
  it('createSpace and listSpaces address {base}spaces/', async () => {
    const description = descriptionWith()
    const { pws, signed } = client({ serviceDescription: description })
    const space = await pws.createSpace({ name: 'Home' })
    expect(signed[0]?.url).toBe(SPACES_URL)
    expect(signed[0]?.method).toBe('POST')
    expect(signed[0]?.json).not.toHaveProperty('type')
    // The handle opens on the response's `Location`.
    expect(space.url).toBe('https://host.example/pws/space/new-space/')

    const typed = client({ serviceDescription: description })
    await typed.pws.createSpace({
      name: 'Clients',
      type: ['AuxiliarySpace', 'Space']
    })
    expect(typed.signed[0]?.json).toMatchObject({
      name: 'Clients',
      type: ['AuxiliarySpace', 'Space']
    })

    const listing = client({
      data: { url: SPACES_URL, totalItems: 0, items: [] },
      serviceDescription: description
    })
    await listing.pws.listSpaces()
    expect(listing.signed[0]?.url).toBe(SPACES_URL)
    expect(listing.signed[0]?.method).toBe('GET')
  })
})
