/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the replica registration API on `Space`
 * (`registerReplica` / `replicas` / `replica` / `deregisterReplica` /
 * `replicaStatus` / `pauseReplica` / `resumeReplica` /
 * `replaceReplicaCapability`), the `replicas` member of the Space Metadata
 * object, the server-managed `created` stamp on the Collection Metadata
 * object, and the read-only `GET` form of the `changes` query. A stub `ZcapClient` captures
 * the request args and returns canned `HttpResponse`s, so no signer or server
 * is involved.
 */
import { describe, it, expect } from 'vitest'
import type { HttpResponse } from '@interop/http-client'

import type {
  ReplicaRegistration,
  ReplicaStatus,
  Space,
  SpaceMetadata
} from '../../src/index.js'
import {
  ConflictError,
  NotFoundError,
  NotSupportedError,
  PreconditionFailedError,
  ProblemTypes,
  ValidationError,
  PwsServerError
} from '../../src/index.js'
import type { RequestArgs } from '../helpers/stubClient.js'
import {
  clientWithRequestSpy,
  clientWithStub,
  jsonResponse,
  spaceUrlFor
} from '../helpers/stubClient.js'

const registration = {
  id: 'peer',
  fromSpace: 'https://source.example/space/reg-src/',
  toSpace: 'https://pws.example/space/s/',
  capability: {
    '@context': 'https://w3id.org/zcap/v1',
    id: 'urn:uuid:1',
    parentCapability: 'urn:zcap:root:x',
    invocationTarget: 'https://source.example/space/reg-src/',
    controller: 'did:key:z6MkServer',
    allowedAction: ['GET'],
    proof: {}
  },
  role: 'source'
} as unknown as ReplicaRegistration

const registrationUrl = 'https://pws.example/space/s/replicas/peer'

/**
 * A thrown `@interop/http-client` error carrying a `problem+json` body of the
 * given type, as the stub's `request` rejects with.
 */
function problem({ status, type }: { status: number; type: string }): object {
  return {
    status,
    response: { status },
    data: { type, title: 'refused', errors: [{ detail: 'why' }] }
  }
}

describe('space.registerReplica()', () => {
  it('POSTs the registration and returns the stored record', async () => {
    const { client, calls } = clientWithRequestSpy({
      data: registration,
      etag: '"1"'
    })
    const result = await client
      .spaceAt(spaceUrlFor('s'))
      .registerReplica(registration)
    expect(calls[0]?.url).toBe('https://pws.example/space/s/replicas')
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.json).toEqual(registration)
    expect(result).toEqual(registration)
  })

  it.each([
    [409, ProblemTypes.REPLICA_REFUSED, ConflictError],
    [409, ProblemTypes.ID_CONFLICT, ConflictError],
    [400, ProblemTypes.INVALID_REQUEST_BODY, ValidationError]
  ])(
    'surfaces a %i %s as a %p told apart by its problem type',
    async (status, type, errorClass) => {
      const client = clientWithStub(() => {
        throw problem({ status, type })
      })
      const attempt = client
        .spaceAt(spaceUrlFor('s'))
        .registerReplica(registration)
      await expect(attempt).rejects.toBeInstanceOf(errorClass)
      await expect(attempt).rejects.toMatchObject({ status, type })
    }
  )
})

describe('replica calls on a 2xx with no JSON body', () => {
  it.each([
    ['registerReplica', (space: Space) => space.registerReplica(registration)],
    ['replicas', (space: Space) => space.replicas()],
    ['replica', (space: Space) => space.replica('peer')],
    ['replicaStatus', (space: Space) => space.replicaStatus('peer')]
  ])(
    '%s throws PwsServerError naming the content type instead of reading it as null',
    async (_name, call) => {
      const client = clientWithStub(() =>
        jsonResponse({ status: 200, headers: { 'content-type': 'text/plain' } })
      )
      const attempt = call(client.spaceAt(spaceUrlFor('s')))
      await expect(attempt).rejects.toBeInstanceOf(PwsServerError)
      await expect(attempt).rejects.toThrow(/text\/plain/)
    }
  )
})

describe('space.replicas()', () => {
  it('GETs the listing and returns it unshaped', async () => {
    const listing = {
      url: '/space/s/replicas',
      totalItems: 1,
      items: [registration]
    }
    const { client, calls } = clientWithRequestSpy({ data: listing })
    const result = await client.spaceAt(spaceUrlFor('s')).replicas()
    expect(calls[0]?.url).toBe('https://pws.example/space/s/replicas')
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(listing)
  })

  it('returns null when the space is missing or the caller is not its controller (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(await client.spaceAt(spaceUrlFor('s')).replicas()).toBeNull()
  })
})

describe('space.replica()', () => {
  it('GETs the per-id path and returns the record', async () => {
    const { client, calls } = clientWithRequestSpy({ data: registration })
    const result = await client.spaceAt(spaceUrlFor('s')).replica('peer')
    expect(calls[0]?.url).toBe(registrationUrl)
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(registration)
  })

  it('percent-encodes the replica id', async () => {
    const { client, calls } = clientWithRequestSpy({ data: registration })
    await client.spaceAt(spaceUrlFor('s')).replica('a b')
    expect(calls[0]?.url).toBe('https://pws.example/space/s/replicas/a%20b')
  })

  it('returns null when the registration is absent (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(await client.spaceAt(spaceUrlFor('s')).replica('missing')).toBeNull()
  })
})

describe('space.deregisterReplica()', () => {
  it('DELETEs the per-id path and reports the removal', async () => {
    const { client, calls } = clientWithRequestSpy()
    const result = await client
      .spaceAt(spaceUrlFor('s'))
      .deregisterReplica('peer')
    expect(calls[0]?.url).toBe(registrationUrl)
    expect(calls[0]?.method).toBe('DELETE')
    expect(result).toEqual({ outcome: 'deleted' })
  })

  it("reports 'not-found' on the masked 404 instead of resolving as success", async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    await expect(
      client.spaceAt(spaceUrlFor('s')).deregisterReplica('missing')
    ).resolves.toEqual({ outcome: 'not-found' })
  })

  it('surfaces the replica-refused removal as a ConflictError', async () => {
    const client = clientWithStub(() => {
      throw problem({ status: 409, type: ProblemTypes.REPLICA_REFUSED })
    })
    await expect(
      client.spaceAt(spaceUrlFor('s')).deregisterReplica('peer')
    ).rejects.toMatchObject({ type: ProblemTypes.REPLICA_REFUSED })
  })
})

describe('space.replicaStatus()', () => {
  it('GETs the status sub-resource and exposes stall.reason', async () => {
    const status: ReplicaStatus = {
      state: 'stalled',
      lastPullAt: '2026-10-05T00:00:00Z',
      collections: [
        { id: 'notes', state: 'synced', lastAppliedAt: '2026-10-05T00:00:00Z' },
        {
          id: 'photos',
          state: 'stalled',
          stall: { reason: 'clock-bound', since: '2026-10-05T00:00:01Z' }
        }
      ]
    }
    const { client, calls } = clientWithRequestSpy({ data: status })
    const result = await client.spaceAt(spaceUrlFor('s')).replicaStatus('peer')
    expect(calls[0]?.url).toBe(
      'https://pws.example/space/s/replicas/peer/status'
    )
    expect(calls[0]?.method).toBe('GET')
    expect(result).toEqual(status)
    expect(result?.collections[1]?.stall?.reason).toBe('clock-bound')
  })

  it('returns null when the registration is absent (404)', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    expect(
      await client.spaceAt(spaceUrlFor('s')).replicaStatus('missing')
    ).toBeNull()
  })
})

/**
 * The stored form of `registration`, as a server serves it back: the write
 * stamp members added, and `pausedAt` when asked for.
 */
function stored(
  members: Partial<ReplicaRegistration> = {}
): ReplicaRegistration {
  return {
    ...registration,
    updatedAt: '2026-10-05T00:00:00.000Z',
    updatedAtCounter: 0,
    originId: 'urn:uuid:origin',
    ...members
  }
}

/**
 * A Space handle over a stub that answers the `GET` of the registration with
 * `record` (under `etag`, when given) and the `PUT` with `put`, recording
 * both. `put` may throw, as the stub's `request` rejects with.
 */
function replaceStub({
  record,
  etag,
  put = () => jsonResponse()
}: {
  record: ReplicaRegistration
  etag?: string
  put?: (args: RequestArgs) => HttpResponse
}): { space: Space; calls: RequestArgs[] } {
  const calls: RequestArgs[] = []
  const client = clientWithStub(args => {
    calls.push(args)
    if (args.method === 'GET') {
      return jsonResponse({
        data: record,
        headers: etag === undefined ? {} : { etag }
      })
    }
    return put(args)
  })
  return { space: client.spaceAt(spaceUrlFor('s')), calls }
}

const nextCapability = {
  ...registration.capability,
  id: 'urn:uuid:2'
} as ReplicaRegistration['capability']

describe('space.pauseReplica()', () => {
  it('reads the registration, then PUTs it back with pausedAt under If-Match', async () => {
    const { space, calls } = replaceStub({ record: stored(), etag: '"1"' })
    await expect(space.pauseReplica('peer')).resolves.toBeUndefined()
    expect(calls.map(call => [call.method, call.url])).toEqual([
      ['GET', registrationUrl],
      ['PUT', registrationUrl]
    ])
    const body = calls[1]?.json as ReplicaRegistration
    expect(body.pausedAt).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/)
    // Every other member goes back as read, the stamp members included: the
    // server ignores those in a write body and judges the rest unchanged.
    const { pausedAt: _pausedAt, ...rest } = body
    expect(rest).toEqual(stored())
    expect(calls[1]?.headers).toEqual({ 'if-match': '"1"' })
  })

  it('throws NotSupportedError and sends no PUT when the read served no ETag', async () => {
    const { space, calls } = replaceStub({ record: stored() })
    await expect(space.pauseReplica('peer')).rejects.toBeInstanceOf(
      NotSupportedError
    )
    expect(calls.map(call => call.method)).toEqual(['GET'])
  })

  it('rebases on a stale If-Match, then surfaces PreconditionFailedError', async () => {
    const { space, calls } = replaceStub({
      record: stored(),
      etag: '"1"',
      put: () => {
        throw problem({ status: 412, type: ProblemTypes.PRECONDITION_FAILED })
      }
    })
    await expect(space.pauseReplica('peer')).rejects.toBeInstanceOf(
      PreconditionFailedError
    )
    // Each lost race re-reads and re-sends, up to the shared attempt limit.
    expect(calls.map(call => call.method)).toEqual([
      'GET',
      'PUT',
      'GET',
      'PUT',
      'GET',
      'PUT'
    ])
  })

  it('throws PwsServerError when the read is a 2xx with no JSON body', async () => {
    const client = clientWithStub(() => jsonResponse())
    await expect(
      client.spaceAt(spaceUrlFor('s')).pauseReplica('peer')
    ).rejects.toBeInstanceOf(PwsServerError)
  })
})

describe('space.resumeReplica()', () => {
  it('PUTs the stored registration back without pausedAt', async () => {
    const { space, calls } = replaceStub({
      record: stored({ pausedAt: '2026-10-05T00:00:01.000Z' }),
      etag: '"2"'
    })
    await space.resumeReplica('peer')
    expect(calls[1]?.method).toBe('PUT')
    expect(calls[1]?.json).toEqual(stored())
    expect(calls[1]?.json).not.toHaveProperty('pausedAt')
    expect(calls[1]?.headers).toEqual({ 'if-match': '"2"' })
  })
})

describe('space.replaceReplicaCapability()', () => {
  it('PUTs the stored registration back with the new capability, keeping pausedAt', async () => {
    const paused = stored({ pausedAt: '2026-10-05T00:00:01.000Z' })
    const { space, calls } = replaceStub({ record: paused, etag: '"3"' })
    await space.replaceReplicaCapability('peer', nextCapability)
    expect(calls[1]?.method).toBe('PUT')
    expect(calls[1]?.url).toBe(registrationUrl)
    expect(calls[1]?.json).toEqual({ ...paused, capability: nextCapability })
    expect(calls[1]?.headers).toEqual({ 'if-match': '"3"' })
  })

  it.each([
    [409, ProblemTypes.REPLICA_REFUSED, ConflictError],
    [400, ProblemTypes.INVALID_REQUEST_BODY, ValidationError]
  ])('maps a %s %s on the PUT to %s', async (status, type, errorClass) => {
    const { space } = replaceStub({
      record: stored(),
      etag: '"1"',
      put: () => {
        throw problem({ status, type })
      }
    })
    const failure = space.replaceReplicaCapability('peer', nextCapability)
    await expect(failure).rejects.toBeInstanceOf(errorClass)
    await expect(failure).rejects.toMatchObject({ type })
  })
})

describe('replica registration changes on the masked 404', () => {
  it.each<[string, (space: Space) => Promise<void>]>([
    ['pauseReplica', space => space.pauseReplica('missing')],
    ['resumeReplica', space => space.resumeReplica('missing')],
    [
      'replaceReplicaCapability',
      space => space.replaceReplicaCapability('missing', nextCapability)
    ]
  ])('%s throws NotFoundError and sends no PUT', async (_name, change) => {
    const { client, calls } = clientWithRequestSpy({ fail: 404 })
    await expect(
      change(client.spaceAt(spaceUrlFor('s')))
    ).rejects.toBeInstanceOf(NotFoundError)
    expect(calls.map(call => call.method)).toEqual(['GET'])
  })
})

describe('space.describe() replicas member', () => {
  it('surfaces the server-derived replicas summaries without shaping', async () => {
    const description: SpaceMetadata = {
      id: 's',
      type: ['Space'],
      controller: 'did:example:alice' as SpaceMetadata['controller'],
      replicas: [
        {
          fromSpace: 'https://source.example/space/reg-src/',
          toSpace: 'https://pws.example/space/s/',
          role: 'source'
        }
      ]
    }
    const { client } = clientWithRequestSpy({ data: description })
    const result = await client.spaceAt(spaceUrlFor('s')).describe()
    expect(result?.replicas).toEqual(description.replicas)
  })
})

describe('collection.meta() created stamp', () => {
  const created = {
    updatedAt: '2026-10-01T00:00:00Z',
    updatedAtCounter: 3,
    originId: 'srv-1'
  }

  it('surfaces the server-managed created stamp', async () => {
    const { client } = clientWithRequestSpy({
      data: { id: 'c', created, custom: {} },
      etag: '"1"'
    })
    const result = await client.spaceAt(spaceUrlFor('s')).collection('c').meta()
    expect(result?.created).toEqual(created)
  })

  it('sends none of the server-managed stamp members the read served', async () => {
    const { client, calls } = clientWithRequestSpy({
      data: {
        id: 'c',
        name: 'Docs',
        createdAt: '2026-10-01T00:00:00Z',
        created,
        updatedAt: '2026-10-02T00:00:00Z',
        updatedAtCounter: 7,
        originId: 'srv-1',
        custom: { name: 'Docs' }
      },
      etag: '"1"'
    })
    const collection = client.spaceAt(spaceUrlFor('s')).collection('c')
    await collection.setMeta({ custom: { name: 'x' } })
    await collection.configure({ name: 'Renamed' })
    const writes = calls.filter(call => call.method === 'PUT')
    expect(writes).toHaveLength(2)
    const stamped = [
      'createdAt',
      'created',
      'updatedAt',
      'updatedAtCounter',
      'originId'
    ]
    for (const write of writes) {
      for (const member of stamped) {
        expect(write.json).not.toHaveProperty(member)
      }
    }
  })
})

describe('collection.changes({ method: "GET" })', () => {
  const page = { documents: [], checkpoint: null }
  // allowedAction: ['GET']
  // A GET and HEAD grant on the collection being read (the signer refuses a
  // capability invoked outside its own target).
  const getOnlyCapability = {
    ...registration.capability,
    invocationTarget: 'https://pws.example/space/s/notes/'
  }

  it('GETs the query endpoint with the parameters in the query string', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    const result = await client
      .spaceAt(spaceUrlFor('s'))
      .collection('notes')
      .changes({ method: 'GET', checkpoint: 'cp/1+=', limit: 10 })
    expect(calls[0]?.method).toBe('GET')
    expect(calls[0]?.url).toBe(
      'https://pws.example/space/s/notes/query?profile=changes&checkpoint=cp%2F1%2B%3D&limit=10'
    )
    expect(calls[0]?.json).toBeUndefined()
    expect(result).toEqual(page)
  })

  it('sends only profile=changes when no checkpoint or limit is given', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    await client
      .spaceAt(spaceUrlFor('s'))
      .collection('notes')
      .changes({ method: 'GET' })
    expect(calls[0]?.url).toBe(
      'https://pws.example/space/s/notes/query?profile=changes'
    )
  })

  it('keeps the POST form by default', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    await client
      .spaceAt(spaceUrlFor('s'))
      .collection('notes')
      .changes({ limit: 5 })
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.url).toBe('https://pws.example/space/s/notes/query')
    expect(calls[0]?.json).toEqual({ profile: 'changes', limit: 5 })
  })

  it('derives the GET form from a bound capability that excludes POST', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    await client
      .spaceAt(spaceUrlFor('s'))
      .collection('notes', { capability: getOnlyCapability })
      .changes({ limit: 5 })
    expect(calls[0]?.method).toBe('GET')
    expect(calls[0]?.url).toBe(
      'https://pws.example/space/s/notes/query?profile=changes&limit=5'
    )
  })

  it('keeps POST under a capability whose actions include POST', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    const capability = { ...getOnlyCapability, allowedAction: 'POST' }
    await client
      .spaceAt(spaceUrlFor('s'))
      .collection('notes', { capability })
      .changes()
    expect(calls[0]?.method).toBe('POST')
  })

  it('walks resourceChanges() in the derived GET form', async () => {
    const { client, calls } = clientWithRequestSpy({ data: page })
    const walk = client
      .spaceAt(spaceUrlFor('s'))
      .collection('notes', { capability: getOnlyCapability })
      .resourceChanges()
    for await (const _entry of walk) {
      // drain
    }
    expect(calls[0]?.method).toBe('GET')
  })

  it('throws (no null-on-404) when the collection is not visible', async () => {
    const { client } = clientWithRequestSpy({ fail: 404 })
    await expect(
      client
        .spaceAt(spaceUrlFor('s'))
        .collection('notes')
        .changes({ method: 'GET' })
    ).rejects.toBeInstanceOf(NotFoundError)
  })
})
