/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `ensureSpaceAndCollection`. The module imports the client only
 * as a type, so at runtime it is pure -- all effects flow through an injected
 * `pws`. These assert the guarded create-if-absent shapes (the `edv`
 * encryption descriptor in particular) and the lost-race recovery behind them,
 * the non-clobbering reads-only behavior over an already-provisioned Space
 * (existing Space description, encryption descriptor, and public policy all
 * left untouched), the refusal of a spec whose mode differs from the standing
 * collection's, the write-free `'governed'` mode, the world-read heal for a
 * public collection, and the labelled-error + `cause` wrapping on failure,
 * without a live server.
 */
import { describe, it, expect } from 'vitest'
import type { CollectionGenerator, PwsClient } from '../../src/index.js'
import {
  ConflictError,
  PreconditionFailedError,
  ValidationError
} from '../../src/index.js'
import { ensureSpace, ensureSpaceAndCollection } from '../../src/sync/index.js'
import { EDV_SCHEME_VERSION } from '../../src/edv/constants.js'
import { spaceUrlFor } from '../helpers/stubClient.js'

interface CollectionDesc {
  name?: string
  backend?: { id: string }
  encryption?: {
    scheme: string
    version: number
    epochs?: { id: string }[]
    history?: { method: string; resource: string }
  }
  generator?: CollectionGenerator
}

class FakeCollection {
  readonly replaceCalls: {
    fields: CollectionDesc
    ifNoneMatch?: boolean
  }[] = []
  describeCalls = 0
  isPublicCalls = 0
  setPublicCalls = 0
  // The served description and its validator, which every applied replace
  // bumps; `collideOnce` lets a test slip a rival write in before ours.
  private state: { current: CollectionDesc | null; version: number }
  constructor(
    private readonly opts: {
      current?: CollectionDesc
      alreadyPublic?: boolean
      failReplace?: Error
      failDescribe?: Error
      // With `failDescribeAfter`, `failDescribe` applies only from that call
      // number on, so a test can let the first read succeed and fail the
      // confirming re-read.
      failDescribeAfter?: number
      collideOnce?: (state: { current: CollectionDesc | null }) => void
    } = {}
  ) {
    this.state = { current: opts.current ?? null, version: 1 }
  }
  describeWithEtag = async (): Promise<{
    description: CollectionDesc
    etag: string
  } | null> => {
    this.describeCalls += 1
    if (
      this.opts.failDescribe &&
      this.describeCalls > (this.opts.failDescribeAfter ?? 0)
    ) {
      throw this.opts.failDescribe
    }
    return this.state.current === null
      ? null
      : { description: this.state.current, etag: `"${this.state.version}"` }
  }
  replaceDescription = async (
    fields: CollectionDesc,
    { ifNoneMatch }: { ifNoneMatch?: boolean } = {}
  ): Promise<{ description: CollectionDesc; etag: string }> => {
    this.replaceCalls.push({
      fields,
      ...(ifNoneMatch !== undefined && { ifNoneMatch })
    })
    if (this.opts.failReplace) {
      throw this.opts.failReplace
    }
    if (this.opts.collideOnce) {
      const collide = this.opts.collideOnce
      this.opts.collideOnce = undefined
      collide(this.state)
      this.state.version += 1
    }
    // The server checks the encryption-descriptor transition before the
    // precondition, so a create carrying the bare descriptor over a rival
    // that already installed key epochs trips those rules first: a 400 for
    // the missing epochs (append-only) is the case modelled here.
    const existing = this.state.current?.encryption
    if (
      fields.encryption !== undefined &&
      existing?.epochs !== undefined &&
      fields.encryption.epochs === undefined
    ) {
      throw new ValidationError('encryption.epochs is append-only', {
        status: 400
      })
    }
    // The guarded create refuses on any present description, the way the
    // server does under `If-None-Match: *`.
    if (ifNoneMatch && this.state.current !== null) {
      throw new PreconditionFailedError('already exists', { status: 412 })
    }
    this.state = { current: fields, version: this.state.version + 1 }
    return { description: fields, etag: `"${this.state.version}"` }
  }
  current(): CollectionDesc | null {
    return this.state.current
  }
  isPublic = async (): Promise<boolean> => {
    this.isPublicCalls += 1
    return this.opts.alreadyPublic ?? false
  }
  setPublic = async (): Promise<void> => {
    this.setPublicCalls += 1
  }
}

interface SpaceDesc {
  id?: string
  type?: string[]
  name?: string
  controller?: string
}

class FakeSpace {
  readonly replaceCalls: { fields: SpaceDesc; ifNoneMatch?: boolean }[] = []
  readonly collectionIds: string[] = []
  readonly collectionObj: FakeCollection
  // The handle's id: the last segment of the Space URL it was opened on.
  readonly id = SPACE
  describeCalls = 0
  private current: SpaceDesc | null
  private readonly failSpace?: Error
  private collideOnce?: (state: { current: SpaceDesc | null }) => void

  constructor(
    opts: {
      current?: SpaceDesc | null
      failSpace?: Error
      collection?: FakeCollection
      collideOnce?: (state: { current: SpaceDesc | null }) => void
    } = {}
  ) {
    this.current = opts.current ?? null
    this.failSpace = opts.failSpace
    this.collideOnce = opts.collideOnce
    this.collectionObj = opts.collection ?? new FakeCollection()
  }

  describe = async (): Promise<SpaceDesc | null> => {
    this.describeCalls += 1
    return this.current
  }

  // The guarded create refuses on any present description, the way the
  // server does under `If-None-Match: *`; `collideOnce` lets a test slip a
  // rival create in before ours. A create answers with the description, the
  // way the server's 201 does.
  replaceDescription = async (
    fields: SpaceDesc,
    { ifNoneMatch }: { ifNoneMatch?: boolean } = {}
  ): Promise<{ description?: SpaceDesc }> => {
    this.replaceCalls.push({
      fields,
      ...(ifNoneMatch !== undefined && { ifNoneMatch })
    })
    if (this.failSpace) {
      throw this.failSpace
    }
    if (this.collideOnce) {
      const collide = this.collideOnce
      this.collideOnce = undefined
      const state = { current: this.current }
      collide(state)
      this.current = state.current
    }
    if (ifNoneMatch && this.current !== null) {
      throw new PreconditionFailedError('already exists', { status: 412 })
    }
    this.current = { id: SPACE, type: ['Space'], ...fields }
    return { description: this.current }
  }

  collection = (id: string): FakeCollection => {
    this.collectionIds.push(id)
    return this.collectionObj
  }
}

class FakePws {
  spaceArg?: string
  // The handle options of every `spaceAt()` call, so a test can assert which
  // capability the handle was built with (or that none was).
  readonly spaceOptions: { capability?: unknown }[] = []
  constructor(private readonly spaceObj: FakeSpace) {}
  spaceAt = (
    spaceUrl: string,
    options: { capability?: unknown } = {}
  ): FakeSpace => {
    this.spaceArg = spaceUrl
    this.spaceOptions.push(options)
    return this.spaceObj
  }
  asClient(): PwsClient {
    return this as unknown as PwsClient
  }
}

const DID = 'did:key:zController'
const SPACE = 'space-abc'
const COLL = 'private-credentials'
const EDV = { scheme: 'edv', version: EDV_SCHEME_VERSION }
// The derived form: a served `encryption` naming the governing log.
const GOVERNED = {
  ...EDV,
  history: { method: 'vh-resource-log', resource: 'https://x/meta/log' }
}

describe('ensureSpaceAndCollection', () => {
  it('creates the absent space then the collection with the edv encryption descriptor', async () => {
    const space = new FakeSpace()
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL
    })

    expect(pws.spaceArg).toBe(spaceUrlFor(SPACE))
    expect(space.describeCalls).toBe(1)
    // Both creates are guarded (`If-None-Match: *`): the server settles the
    // race, not a client-side re-read and merge.
    expect(space.replaceCalls).toEqual([
      { fields: { name: 'PWS Space', controller: DID }, ifNoneMatch: true }
    ])
    expect(space.collectionIds).toEqual([COLL])
    expect(space.collectionObj.describeCalls).toBe(1)
    expect(space.collectionObj.replaceCalls).toEqual([
      { fields: { name: COLL, encryption: EDV }, ifNoneMatch: true }
    ])
    expect(space.collectionObj.setPublicCalls).toBe(0)
  })

  it('adopts a rival Space create that lands between the read and the guarded PUT', async () => {
    const space = new FakeSpace({
      collideOnce: state => {
        state.current = { id: SPACE, name: 'Rival', controller: DID }
      }
    })
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL
    })
    // The lost race is a re-read, not an error, and the winner is kept.
    expect(space.replaceCalls).toHaveLength(1)
    expect(space.describeCalls).toBe(2)
    expect(await space.describe()).toMatchObject({ name: 'Rival' })
    // The collection half still ran.
    expect(space.collectionObj.replaceCalls).toHaveLength(1)
  })

  it('adopts a rival collection create that lands between the read and the guarded PUT', async () => {
    const collection = new FakeCollection({
      collideOnce: state => {
        state.current = {
          name: 'Rival',
          backend: { id: 'urn:backend:blob' },
          encryption: EDV
        }
      }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL
    })
    // The guarded create lost; the re-read found the rival's encrypted
    // collection and adopted it as-is, with no second write.
    expect(collection.describeCalls).toBe(2)
    expect(collection.replaceCalls).toEqual([
      { fields: { name: COLL, encryption: EDV }, ifNoneMatch: true }
    ])
    expect(collection.current()).toEqual({
      name: 'Rival',
      backend: { id: 'urn:backend:blob' },
      encryption: EDV
    })
  })

  it('refuses a descriptor-less rival that won the create race', async () => {
    const collection = new FakeCollection({
      collideOnce: state => {
        state.current = { name: 'Rival' }
      }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await expect(
      ensureSpaceAndCollection({
        pws: new FakePws(space).asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toBeInstanceOf(ValidationError)
    // The guarded create had already gone out when the rival was read back.
    // Nothing follows it, and the rival's collection is kept.
    expect(collection.replaceCalls).toEqual([
      { fields: { name: COLL, encryption: EDV }, ifNoneMatch: true }
    ])
    expect(collection.current()).toEqual({ name: 'Rival' })
  })

  it('adopts a rival collection create that already installed key epochs', async () => {
    // The rival ran `ensureFirstEpoch` before the loser's PUT arrived, so the
    // server answers the loser's bare descriptor with the epoch-transition
    // 400, not the precondition's 412; the re-read still adopts the winner.
    const rivalDescriptor = {
      scheme: 'edv',
      version: EDV_SCHEME_VERSION,
      epochs: [{ id: 'epoch-0' }]
    }
    const collection = new FakeCollection({
      collideOnce: state => {
        state.current = { name: 'Rival', encryption: rivalDescriptor }
      }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL
    })
    expect(collection.replaceCalls).toHaveLength(1)
    expect(collection.describeCalls).toBe(2)
    expect(collection.current()!.encryption).toEqual(rivalDescriptor)
  })

  it('rethrows a create failure when nothing can be read back', async () => {
    // A failed create with no collection behind it is a genuine failure, not
    // a lost race: the re-read finds nothing and the original error keeps
    // its type.
    const cause = new ConflictError('backend unknown', { status: 409 })
    const collection = new FakeCollection({ failReplace: cause })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await expect(
      ensureSpaceAndCollection({
        pws: new FakePws(space).asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toBe(cause)
    expect(collection.describeCalls).toBe(2)
  })

  it('keeps the create failure when the confirming re-read fails too', async () => {
    // Both halves failing is usually one outage. The create's own error is
    // the actionable one and the typed error this path exists to preserve, so
    // it must win over the re-read's generic failure.
    const cause = new ConflictError('encryption-immutable', { status: 409 })
    const collection = new FakeCollection({
      failReplace: cause,
      failDescribe: new Error('connection reset'),
      failDescribeAfter: 1
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await expect(
      ensureSpaceAndCollection({
        pws: new FakePws(space).asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toBe(cause)
    expect(collection.describeCalls).toBe(2)
  })

  it('creates a plaintext public collection without the descriptor and grants world read', async () => {
    const space = new FakeSpace()
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: 'public-credentials',
      encryption: 'plaintext',
      isPublic: true
    })

    expect(space.collectionObj.replaceCalls).toEqual([
      { fields: { name: 'public-credentials' }, ifNoneMatch: true }
    ])
    // A just-created collection has no policy yet, so the read is skipped.
    expect(space.collectionObj.isPublicCalls).toBe(0)
    expect(space.collectionObj.setPublicCalls).toBe(1)
  })

  it('issues only reads over a fully settled space and collection', async () => {
    const space = new FakeSpace({
      current: { name: 'Wallet Space', controller: 'did:webvh:other' },
      collection: new FakeCollection({
        current: { name: 'Verifiable Credentials', encryption: EDV }
      })
    })
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL
    })

    // Neither the existing Space description (its controller in particular)
    // nor the existing encryption descriptor is re-sent.
    expect(space.describeCalls).toBe(1)
    expect(space.replaceCalls).toEqual([])
    expect(space.collectionObj.describeCalls).toBe(1)
    expect(space.collectionObj.replaceCalls).toEqual([])
  })

  it('refuses to declare encryption on an existing descriptor-less collection', async () => {
    // `encryption` is creation-only on the server, so the client refuses
    // before any write rather than sending one the server must refuse.
    const collection = new FakeCollection({
      current: { name: 'Kept Name', generator: { id: 'did:key:zApp' } }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await expect(
      ensureSpaceAndCollection({
        pws: new FakePws(space).asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL,
        isPublic: true
      })
    ).rejects.toMatchObject({
      name: 'ValidationError',
      // The message names both readings of a descriptor-less collection: a
      // governed one whose log is not created yet, and a plaintext one.
      message: expect.stringMatching(
        /encryption: 'governed'.*create a new Collection and copy its Resources into it\./
      )
    })
    expect(collection.replaceCalls).toEqual([])
    expect(collection.describeCalls).toBe(1)
    // The world-read step is not reached either.
    expect(collection.isPublicCalls).toBe(0)
    expect(collection.setPublicCalls).toBe(0)
    expect(collection.current()).toEqual({
      name: 'Kept Name',
      generator: { id: 'did:key:zApp' }
    })
  })

  it('keeps an existing backend on an encrypted collection, writing nothing', async () => {
    const collection = new FakeCollection({
      current: {
        name: COLL,
        backend: { id: 'urn:backend:blob' },
        encryption: EDV
      }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL
    })
    expect(collection.replaceCalls).toEqual([])
    expect(collection.current()).toEqual({
      name: COLL,
      backend: { id: 'urn:backend:blob' },
      encryption: EDV
    })
  })

  it('creates a governed collection with no encryption member', async () => {
    const space = new FakeSpace()
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed'
    })

    // The same descriptor-less create the plaintext branch makes: a governed
    // Collection's `encryption` member is the server's to derive from the
    // history log, so the client declares none.
    expect(space.collectionObj.replaceCalls).toEqual([
      { fields: { name: COLL }, ifNoneMatch: true }
    ])
  })

  it('writes nothing to an existing descriptor-less collection when governed', async () => {
    const collection = new FakeCollection({ current: { name: COLL } })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed'
    })

    // No descriptor is declared: the server refuses to govern a Description
    // that already carries a client-written descriptor.
    expect(collection.replaceCalls).toEqual([])
    expect(collection.describeCalls).toBe(1)
    expect(collection.current()).toEqual({ name: COLL })
  })

  it.each([
    // The server keeps a declared descriptor immutable, so the caller's log
    // create would fail with its 409; the misfit is named here instead.
    {
      requested: 'governed',
      standingName: 'client-written',
      standing: EDV,
      reason: 'cannot be governed'
    },
    {
      requested: 'plaintext',
      standingName: 'client-written',
      standing: EDV,
      reason: 'is not plaintext'
    },
    {
      requested: 'edv',
      standingName: 'governed',
      standing: GOVERNED,
      reason: 'is governed by a history log'
    },
    {
      requested: 'plaintext',
      standingName: 'governed',
      standing: GOVERNED,
      reason: 'is governed by a history log'
    }
  ] as const)(
    'refuses a $requested spec over a collection carrying a $standingName descriptor',
    async ({ requested, standing, reason }) => {
      const collection = new FakeCollection({
        current: { name: COLL, encryption: standing }
      })
      const space = new FakeSpace({
        current: { name: 'Wallet Space' },
        collection
      })
      await expect(
        ensureSpaceAndCollection({
          pws: new FakePws(space).asClient(),
          spaceUrl: spaceUrlFor(SPACE),
          controllerDid: DID,
          collectionId: COLL,
          encryption: requested,
          isPublic: true
        })
      ).rejects.toMatchObject({
        name: 'ValidationError',
        message: expect.stringContaining(reason)
      })
      expect(collection.replaceCalls).toEqual([])
      expect(collection.setPublicCalls).toBe(0)
    }
  )

  it('writes nothing to an already governed collection', async () => {
    const collection = new FakeCollection({
      current: { name: COLL, encryption: GOVERNED }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed'
    })

    // A Description PUT may not carry the derived member, so nothing is sent.
    expect(collection.replaceCalls).toEqual([])
    expect(collection.current()!.encryption).toBe(GOVERNED)
  })

  it('leaves an existing encryption descriptor untouched on re-run', async () => {
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      // A descriptor another client appended key epochs to: re-sending the
      // bare descriptor would drop them.
      collection: new FakeCollection({
        current: { name: COLL, encryption: EDV }
      })
    })
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL
    })
    expect(space.replaceCalls).toEqual([])
    expect(space.collectionObj.replaceCalls).toEqual([])
    expect(space.collectionObj.current()!.encryption).toBe(EDV)
  })

  it('heals a missing world-read grant on an existing public collection', async () => {
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection: new FakeCollection({
        current: { name: 'public-credentials' },
        alreadyPublic: false
      })
    })
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: 'public-credentials',
      encryption: 'plaintext',
      isPublic: true
    })

    expect(space.collectionObj.setPublicCalls).toBe(1)
  })

  it('does not re-grant world read when the policy already says public', async () => {
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection: new FakeCollection({
        current: { name: 'public-credentials' },
        alreadyPublic: true
      })
    })
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: 'public-credentials',
      encryption: 'plaintext',
      isPublic: true
    })

    expect(space.collectionObj.isPublicCalls).toBe(1)
    expect(space.collectionObj.setPublicCalls).toBe(0)
  })

  it('is idempotent: a re-run over what the first run created issues no writes', async () => {
    const freshSpace = new FakeSpace()
    await ensureSpaceAndCollection({
      pws: new FakePws(freshSpace).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL
    })
    expect(freshSpace.replaceCalls).toHaveLength(1)
    expect(freshSpace.collectionObj.replaceCalls).toHaveLength(1)

    // The second run reads the state the first run left behind.
    await ensureSpaceAndCollection({
      pws: new FakePws(freshSpace).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL
    })
    expect(freshSpace.replaceCalls).toHaveLength(1)
    expect(freshSpace.collectionObj.replaceCalls).toHaveLength(1)
  })

  it('honours a custom space name', async () => {
    const space = new FakeSpace()
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      spaceName: 'My Space'
    })
    expect(space.replaceCalls[0]!.fields.name).toBe('My Space')
  })

  it('honours a custom collection display name', async () => {
    const space = new FakeSpace()
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      collectionName: 'Verifiable Credentials'
    })
    expect(space.collectionObj.replaceCalls[0]!.fields.name).toBe(
      'Verifiable Credentials'
    )
  })

  it('wraps a space create failure with a labelled error + cause', async () => {
    const cause = new Error('space boom')
    const pws = new FakePws(new FakeSpace({ failSpace: cause }))
    await expect(
      ensureSpaceAndCollection({
        pws: pws.asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toMatchObject({
      message: expect.stringContaining(
        'Failed to configure PWS space "https://pws.example/space/space-abc/"'
      ),
      cause
    })
  })

  it('does not attempt the collection when the space create fails', async () => {
    const space = new FakeSpace({ failSpace: new Error('nope') })
    const pws = new FakePws(space)
    await expect(
      ensureSpaceAndCollection({
        pws: pws.asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toThrow()
    expect(space.collectionIds).toEqual([])
  })

  it('wraps a collection create failure with a labelled error + cause', async () => {
    const cause = new Error('collection boom')
    const space = new FakeSpace({
      collection: new FakeCollection({ failReplace: cause })
    })
    const pws = new FakePws(space)
    await expect(
      ensureSpaceAndCollection({
        pws: pws.asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toMatchObject({
      message: expect.stringContaining(
        'Failed to configure collection "private-credentials" in space "https://pws.example/space/space-abc/"'
      ),
      cause
    })
  })

  it('wraps a collection.describe failure with a labelled error + cause', async () => {
    const cause = new Error('describe boom')
    const space = new FakeSpace({
      collection: new FakeCollection({ failDescribe: cause })
    })
    const pws = new FakePws(space)
    await expect(
      ensureSpaceAndCollection({
        pws: pws.asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL
      })
    ).rejects.toMatchObject({
      message: expect.stringContaining(
        'Failed to configure collection "private-credentials" in space "https://pws.example/space/space-abc/"'
      ),
      cause
    })
  })
})

describe('ensureSpaceAndCollection created result', () => {
  it('resolves created true when its own guarded create made the collection', async () => {
    const space = new FakeSpace({ current: { name: 'Wallet Space' } })
    const result = await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'plaintext'
    })
    expect(result).toEqual({ created: true })
  })

  it('resolves created false when the collection already stands', async () => {
    const collection = new FakeCollection({ current: { name: COLL } })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    const result = await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'plaintext'
    })
    expect(result).toEqual({ created: false })
    expect(collection.replaceCalls).toHaveLength(0)
  })

  it('resolves created false when it loses the create race and adopts the rival', async () => {
    const collection = new FakeCollection({
      collideOnce: state => {
        state.current = { name: 'Rival' }
      }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    const result = await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'plaintext',
      isPublic: true
    })
    expect(result).toEqual({ created: false })
    // The guarded create was attempted and refused; the rival is kept.
    expect(collection.replaceCalls).toHaveLength(1)
    expect(collection.current()).toEqual({ name: 'Rival' })
    // A lost race reads the policy before granting world read.
    expect(collection.isPublicCalls).toBe(1)
    expect(collection.setPublicCalls).toBe(1)
  })
})

describe('ensureSpaceAndCollection app attribution', () => {
  const APP: CollectionGenerator = {
    id: 'did:key:zApp',
    origin: 'https://app.example',
    url: 'https://app.example/notes'
  }

  it('stamps the generator on the guarded create', async () => {
    const space = new FakeSpace()
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      generator: APP
    })

    expect(space.collectionObj.replaceCalls).toEqual([
      {
        fields: {
          name: COLL,
          encryption: EDV,
          generator: APP
        },
        ifNoneMatch: true
      }
    ])
  })

  it('stamps the generator on a descriptor-less create', async () => {
    const space = new FakeSpace()
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed',
      generator: APP
    })

    expect(space.collectionObj.replaceCalls).toEqual([
      {
        fields: { name: COLL, generator: APP },
        ifNoneMatch: true
      }
    ])
  })

  it('writes nothing when the standing collection already carries a generator', async () => {
    const collection = new FakeCollection({
      current: {
        name: COLL,
        encryption: EDV,
        generator: APP
      }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      generator: APP
    })

    expect(collection.replaceCalls).toEqual([])
    expect(collection.describeCalls).toBe(1)
  })

  it("leaves a standing attributed collection's generator unchanged when a different generator is supplied", async () => {
    // Attribution is stamped on the create only: the creator of a standing
    // collection is never renamed by a later ensure.
    const collection = new FakeCollection({
      current: {
        name: COLL,
        encryption: EDV,
        generator: APP
      }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      generator: {
        id: 'did:key:zOtherApp',
        origin: 'https://other.example'
      }
    })

    expect(collection.replaceCalls).toEqual([])
    expect(collection.current()).toMatchObject({
      generator: APP
    })
  })

  it('does not backfill a generator onto a standing unattributed collection', async () => {
    const collection = new FakeCollection({
      current: { name: COLL, encryption: EDV }
    })
    const space = new FakeSpace({
      current: { name: 'Wallet Space' },
      collection
    })
    await ensureSpaceAndCollection({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      generator: APP
    })

    expect(collection.replaceCalls).toEqual([])
  })
})

describe('ensureSpace', () => {
  it('creates the absent space and returns the description it wrote', async () => {
    const space = new FakeSpace()
    const pws = new FakePws(space)
    const description = await ensureSpace({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID
    })

    expect(space.describeCalls).toBe(1)
    expect(space.replaceCalls).toEqual([
      { fields: { name: 'PWS Space', controller: DID }, ifNoneMatch: true }
    ])
    expect(description).toMatchObject({ id: SPACE, controller: DID })
  })

  it('returns the rival description when the guarded create loses the race', async () => {
    // The realistic rival is another client of the same controller (the
    // Space id is minted for that DID): a rival under another controller
    // would fail the loser's authorization before the precondition is
    // evaluated, so the server answers that case with no 412.
    const rival = { id: SPACE, name: 'Rival', controller: DID }
    const space = new FakeSpace({
      collideOnce: state => {
        state.current = rival
      }
    })
    const description = await ensureSpace({
      pws: new FakePws(space).asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID
    })
    expect(space.replaceCalls).toHaveLength(1)
    expect(space.describeCalls).toBe(2)
    expect(description).toBe(rival)
  })

  it('returns an existing description without writing anything', async () => {
    // `id` is not decoration: every server write path stamps it from the URL
    // segment, so a served description always carries it -- and it is what
    // `ensureSpaceAndCollection` checks the threaded description against.
    const current = {
      id: SPACE,
      name: 'Wallet Space',
      controller: 'did:webvh:other'
    }
    const space = new FakeSpace({ current })
    const pws = new FakePws(space)
    const description = await ensureSpace({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID
    })

    expect(space.describeCalls).toBe(1)
    expect(space.replaceCalls).toEqual([])
    expect(description).toBe(current)
  })

  it('wraps a failure with the space-labelled error + cause', async () => {
    const cause = new Error('space boom')
    const space = new FakeSpace({ failSpace: cause })
    const pws = new FakePws(space)
    await expect(
      ensureSpace({
        pws: pws.asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID
      })
    ).rejects.toMatchObject({
      message: expect.stringContaining(
        'Failed to configure PWS space "https://pws.example/space/space-abc/"'
      ),
      cause
    })
  })
})

describe('ensureSpaceAndCollection with an invocation capability', () => {
  const CAPABILITY = { id: 'urn:zcap:delegated' }

  it('builds every Space handle with the capability, on both ensures', async () => {
    const pws = new FakePws(new FakeSpace())
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed',
      capability: CAPABILITY as never
    })
    // One handle for the collection half, one inside `ensureSpace`.
    expect(pws.spaceOptions).toHaveLength(2)
    for (const options of pws.spaceOptions) {
      expect(options.capability).toBe(CAPABILITY)
    }
  })

  it('rides the capability past a supplied space description', async () => {
    const pws = new FakePws(new FakeSpace({ current: null }))
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      encryption: 'governed',
      spaceDescription: { id: SPACE, type: ['Space'], controller: DID },
      capability: CAPABILITY as never
    })
    expect(pws.spaceOptions).toEqual([{ capability: CAPABILITY }])
  })

  it('builds the handle with no capability when none is given', async () => {
    const pws = new FakePws(new FakeSpace())
    await ensureSpace({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID
    })
    expect(pws.spaceOptions).toEqual([{ capability: undefined }])
  })
})

describe('ensureSpaceAndCollection with a supplied space description', () => {
  it('accepts what ensureSpace returned, on both of its paths', async () => {
    // The two functions are halves of one seam, so assert them joined rather
    // than only side by side: whatever `ensureSpace` hands back must satisfy
    // `ensureSpaceAndCollection`'s check. Testing each half against its own
    // hand-written description is what let an id-less fixture pass while the
    // join would have thrown.
    for (const current of [
      null,
      { id: SPACE, name: 'Wallet Space', controller: 'did:webvh:other' }
    ]) {
      const space = new FakeSpace({ current })
      const pws = new FakePws(space)
      const spaceDescription = await ensureSpace({
        pws: pws.asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID
      })
      await ensureSpaceAndCollection({
        pws: pws.asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL,
        spaceDescription
      })
      // One describe from the ensure, none from the collection branch.
      expect(space.describeCalls).toBe(1)
    }
  })

  it('refuses a description naming another space', async () => {
    const space = new FakeSpace()
    const pws = new FakePws(space)
    await expect(
      ensureSpaceAndCollection({
        pws: pws.asClient(),
        spaceUrl: spaceUrlFor(SPACE),
        controllerDid: DID,
        collectionId: COLL,
        spaceDescription: {
          id: 'space-somewhere-else',
          type: ['Space'],
          controller: DID
        } as never
      })
    ).rejects.toMatchObject({
      name: 'ValidationError',
      message: expect.stringContaining('space-somewhere-else')
    })
    expect(space.describeCalls).toBe(0)
  })

  it('skips the space half entirely', async () => {
    const space = new FakeSpace()
    const pws = new FakePws(space)
    await ensureSpaceAndCollection({
      pws: pws.asClient(),
      spaceUrl: spaceUrlFor(SPACE),
      controllerDid: DID,
      collectionId: COLL,
      spaceDescription: {
        id: SPACE,
        type: ['Space'],
        controller: DID
      } as never
    })

    // The whole point of threading: an already-ensured Space is neither
    // described nor configured again, however many collections fan out.
    expect(space.describeCalls).toBe(0)
    expect(space.replaceCalls).toEqual([])
    expect(space.collectionObj.replaceCalls).toEqual([
      { fields: { name: COLL, encryption: EDV }, ifNoneMatch: true }
    ])
  })
})
