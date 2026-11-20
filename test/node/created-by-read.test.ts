/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the `createdBy` check on the handle reads. `describe()` on a
 * Space and a Collection, `meta()` on a Collection and a Resource, and the
 * `changes()` / `documents()` feed reads hand `createdBy` to the caller only
 * as a non-empty array of DIDs, and leave any other served value off.
 */
import { describe, it, expect } from 'vitest'

import { withCheckedCreatedBy } from '../../src/internal/createdBy.js'
import { feedEntry } from '../helpers/changesFeed.js'
import type { RequestArgs } from '../helpers/stubClient.js'
import {
  clientWithStub,
  jsonResponse,
  spaceUrlFor
} from '../helpers/stubClient.js'

const SPACE = 'space-abc'
const COLL = 'credentials'

/**
 * `createdBy` values no read hands on: anything other than a non-empty array
 * of DID strings.
 */
const REFUSED_CREATED_BY: [string, unknown][] = [
  ['a single DID string', 'did:key:zCreator'],
  ['an empty array', []],
  ['an array with a non-DID entry', ['did:key:zUser', 'not-a-did']],
  ['a number', 42]
]

/**
 * The handles of a stub server that serves `createdBy` on every metadata
 * object and on every feed entry.
 *
 * @param createdBy {unknown}
 * @returns {object}
 */
function handlesServing(createdBy: unknown) {
  const pws = clientWithStub((args: RequestArgs) => {
    if (args.url?.includes('/query') === true) {
      return jsonResponse({
        data: {
          documents: [
            { ...feedEntry({ id: 'a', checkpoint: 'c1', data: {} }), createdBy }
          ],
          checkpoint: null
        }
      })
    }
    return jsonResponse({
      data: { id: COLL, type: ['Collection'], createdBy },
      headers: { etag: '"v1"' }
    })
  })
  const space = pws.spaceAt(spaceUrlFor(SPACE))
  const collection = space.collection(COLL)
  return { space, collection, resource: collection.resource('a') }
}

describe('withCheckedCreatedBy', () => {
  it('returns an object with a createdBy list as it is', () => {
    const served = { id: 'a', createdBy: ['did:key:zUser', 'did:key:zApp'] }
    expect(withCheckedCreatedBy(served)).toBe(served)
  })

  it('returns an object with no createdBy as it is', () => {
    const served = { id: 'a' }
    expect(withCheckedCreatedBy(served)).toBe(served)
  })

  it.each(REFUSED_CREATED_BY)(
    'leaves createdBy off when it is %s, without modifying the served object',
    (_label, createdBy) => {
      const served = { id: 'a', createdBy }
      expect(withCheckedCreatedBy(served)).toEqual({ id: 'a' })
      expect(served.createdBy).toBe(createdBy)
    }
  )
})

describe('createdBy on the handle reads', () => {
  it('is carried as a list by every read', async () => {
    const createdBy = ['did:key:zUser', 'did:key:zApp']
    const { space, collection, resource } = handlesServing(createdBy)

    expect((await space.describe())?.createdBy).toEqual(createdBy)
    expect((await space.describeWithEtag())?.description.createdBy).toEqual(
      createdBy
    )
    expect((await collection.describe())?.createdBy).toEqual(createdBy)
    expect((await collection.meta())?.createdBy).toEqual(createdBy)
    expect((await resource.meta())?.createdBy).toEqual(createdBy)
    const page = await collection.changes()
    expect(page.documents[0]).toHaveProperty('createdBy', createdBy)
    expect((await collection.documents())?.[0]?.createdBy).toEqual(createdBy)
  })

  it.each(REFUSED_CREATED_BY)(
    'is left off every read when the server serves %s',
    async (_label, createdBy) => {
      const { space, collection, resource } = handlesServing(createdBy)

      expect(await space.describe()).not.toHaveProperty('createdBy')
      const described = await space.describeWithEtag()
      expect(described?.description).not.toHaveProperty('createdBy')
      expect(await collection.describe()).not.toHaveProperty('createdBy')
      expect(await collection.meta()).not.toHaveProperty('createdBy')
      expect(await resource.meta()).not.toHaveProperty('createdBy')
      const page = await collection.changes()
      expect(page.documents).toHaveLength(1)
      expect(page.documents[0]).not.toHaveProperty('createdBy')
      const documents = await collection.documents()
      expect(documents).toHaveLength(1)
      expect(documents?.[0]).not.toHaveProperty('createdBy')
    }
  )
})
