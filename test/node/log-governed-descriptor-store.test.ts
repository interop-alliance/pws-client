/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the log-governed descriptor store (no network): the
 * `EncryptionDescriptorStore` over a Collection whose served `encryption`
 * member is the point-state projection of its governing history log. Covers
 * the plain-descriptor passthrough (a projection without `history` behaves
 * as the Collection Metadata adapter does), the governed lifecycle driven
 * by the recipient primitives (genesis create, verified read, signed append,
 * chain-head pin), the read-only store, the forwarded seal, and the refusals:
 * `history.method` and `history.resource` mismatches before any fetch, a
 * projection that does not match the verified head (a stale one is the port's
 * conflict, a forged one an integrity refusal), a head of the wrong state
 * type on read, seal, an adopting create, and a replace read-back, an absent
 * log under a projection, and the library's own integrity and continuity
 * refusals passing through unwrapped.
 */
import { describe, it, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import type { ResourceLogEntry } from '@interop/storage-core'
import {
  buildResourceLogEntry,
  memoryResourceLogPinStore,
  parseResourceLog,
  serializeResourceLog,
  type ResourceLogController,
  type ResourceLogSigner
} from '@interop/vh-resource-log'
import {
  fakeController,
  memoryLogStore
} from '@interop/vh-resource-log/testing'

import {
  NotSupportedError,
  PreconditionFailedError,
  ValidationError
} from '../../src/index.js'
import type { CollectionEncryption } from '../../src/index.js'
import type { Collection } from '../../src/Collection.js'
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  logGovernedCollectionDescriptorStore,
  logGovernedDescriptorStore,
  toEpochConfigurationState
} from '../../src/edv/logGovernedDescriptorStore.js'
import { addRecipient, initRecipients } from '../../src/edv/recipients.js'
import type { RecipientPublicKey } from '../../src/edv/recipients.js'

const LOG_URL = 'https://pws.example/space/s1/vault/meta/log'
const LOG_ID = 'space/s1/vault/meta/log'
const OLD_STATE_TYPE = 'WasEpochConfiguration'

/**
 * The format identifier a genesis entry's `parameters` carry (absent on a
 * non-genesis entry's parameters shape).
 *
 * @param entry {ResourceLogEntry}
 * @returns {string | undefined}
 */
function genesisMethod(entry: ResourceLogEntry): string | undefined {
  const parameters = entry.parameters as { method?: string } | undefined
  return parameters?.method
}

/**
 * A self-describing did:key X25519 reader (see descriptor-store.test.ts).
 *
 * @returns {Promise<{ kak: IKeyAgreementKey; recipient: RecipientPublicKey }>}
 */
async function makeReader(): Promise<{
  kak: IKeyAgreementKey
  recipient: RecipientPublicKey
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const publicKeyMultibase = kak.publicKeyMultibase
  const did = `did:key:${publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${publicKeyMultibase}`
  return {
    kak: kak as IKeyAgreementKey,
    recipient: { id: kak.id, publicKeyMultibase }
  }
}

/**
 * An Ed25519 log signer plus a one-version controller view that lists it.
 *
 * @returns {Promise<{ signer: ResourceLogSigner; controller: ResourceLogController }>}
 */
async function makeWriter(): Promise<{
  signer: ResourceLogSigner
  controller: ResourceLogController
}> {
  const signingKey = await Ed25519VerificationKey.generate()
  const keyMultibase = signingKey.publicKeyMultibase as string
  const keySigner = signingKey.didKeySigner()
  const signer: ResourceLogSigner = {
    keyMultibase,
    async sign({ data }) {
      return keySigner.sign({ data })
    }
  }
  const controller = fakeController({
    versions: [{ versionId: '1-a', keys: [keyMultibase] }]
  })
  return { signer, controller }
}

/**
 * `entries` plus a properly signed and hashed append whose state carries
 * `stateType`: the library's integrity and continuity checks both pass, so the
 * store's own type rule is the only thing left to refuse it.
 *
 * @param options {object}
 * @param options.entries {ResourceLogEntry[]}
 * @param options.controller {ResourceLogController}
 * @param options.signer {ResourceLogSigner}
 * @param [options.stateType] {string}
 * @returns {Promise<ResourceLogEntry[]>}
 */
async function withForeignHead({
  entries,
  controller,
  signer,
  stateType = OLD_STATE_TYPE
}: {
  entries: ResourceLogEntry[]
  controller: ResourceLogController
  signer: ResourceLogSigner
  stateType?: string
}): Promise<ResourceLogEntry[]> {
  const head = entries.at(-1)!
  const foreign = await buildResourceLogEntry({
    head,
    state: { ...head.state, type: stateType },
    controller,
    signer
  })
  return [...entries, foreign]
}

/**
 * An in-memory fake of the Collection surface the governed store drives. The
 * served Description's `encryption` member is derived the way the server
 * derives it: the log head's `state` with `history` stamped on, or the
 * point-state descriptor when the collection is not log-governed. Control
 * seams let a test serve a tampered projection or rewrite the stored log.
 *
 * @param [options] {object}
 * @param [options.encryption] {CollectionEncryption}   a point-state
 *   descriptor for a collection that is not log-governed
 * @returns {object}
 */
function fakeGovernedCollection(
  options: { encryption?: CollectionEncryption } = {}
) {
  const state = {
    body: undefined as string | undefined,
    version: 0,
    encryption: options.encryption,
    projection: undefined as CollectionEncryption | undefined,
    logReads: 0,
    descriptionPuts: [] as Array<{
      description: Record<string, unknown>
      ifMatch?: string
    }>,
    logPuts: [] as Array<{ ifMatch?: string; ifNoneMatch?: boolean }>
  }
  const etag = () => `"v${state.version}"`
  function served(): CollectionEncryption | undefined {
    if (state.projection !== undefined) {
      return state.projection
    }
    if (state.body === undefined) {
      return state.encryption
    }
    const entries = parseResourceLog(state.body)
    const head = entries[entries.length - 1]!
    const method = genesisMethod(entries[0]!)
    return {
      ...(head.state as unknown as CollectionEncryption),
      ...(method !== undefined && { history: { method, resource: LOG_URL } })
    }
  }
  const collection = {
    id: 'vault',
    spaceId: 's1',
    historyLogUrl: LOG_URL,
    describeWithEtag: async () => ({
      description: {
        type: ['Collection'],
        name: 'Vault',
        generator: { id: 'did:key:zApp', origin: 'https://app.example' },
        encryption: served()
      },
      etag: etag()
    }),
    replaceDescription: async (
      description: Record<string, unknown>,
      options: { ifMatch?: string } = {}
    ) => {
      state.descriptionPuts.push({ description, ifMatch: options.ifMatch })
      if (options.ifMatch !== undefined && options.ifMatch !== etag()) {
        throw new PreconditionFailedError('stale', { status: 412 })
      }
      state.encryption = description.encryption as CollectionEncryption
      state.version += 1
      return { description, etag: etag() }
    },
    getHistoryLog: async () => {
      state.logReads += 1
      return state.body === undefined
        ? null
        : { body: state.body, etag: etag() }
    },
    putHistoryLog: async (
      body: string,
      options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
    ) => {
      state.logPuts.push(options)
      if (options.ifNoneMatch && state.body !== undefined) {
        throw new PreconditionFailedError('exists', { status: 412 })
      }
      if (options.ifMatch !== undefined && options.ifMatch !== etag()) {
        throw new PreconditionFailedError('stale', { status: 412 })
      }
      state.body = body
      state.version += 1
      return { etag: etag() }
    },
    _entries: () =>
      state.body === undefined ? [] : parseResourceLog(state.body),
    _setEntries: (entries: ResourceLogEntry[]) => {
      state.body = serializeResourceLog(entries)
      state.version += 1
    },
    _state: state
  }
  return { collection: collection as unknown as Collection, fake: collection }
}

/**
 * A governed collection carrying a one-epoch log for `reader`, plus the
 * writer and pin store that produced it, and a fresh store over it.
 *
 * @returns {Promise<object>}
 */
/**
 * A controller view that counts its document dereferences. The verifier
 * dereferences the controller document once per entry it checks proofs on,
 * so the count is the number of entries verified.
 */
function countingController(view: ResourceLogController): {
  controller: ResourceLogController
  calls: number
} {
  const counted = {
    calls: 0,
    controller: {
      ...view,
      async documentAt(versionId?: string) {
        counted.calls++
        return view.documentAt(versionId)
      }
    }
  }
  return counted
}

async function governedFixture() {
  const reader = await makeReader()
  const writer = await makeWriter()
  const pinStore = memoryResourceLogPinStore()
  const { collection, fake } = fakeGovernedCollection()
  const storeOptions = {
    collection,
    resolveController: async () => writer.controller,
    pinStore,
    logId: LOG_ID
  }
  const descriptor = await initRecipients({
    store: logGovernedCollectionDescriptorStore({
      ...storeOptions,
      signer: writer.signer
    }),
    recipients: [reader.recipient]
  })
  return {
    reader,
    writer,
    pinStore,
    collection,
    fake,
    storeOptions,
    descriptor
  }
}

describe('logGovernedCollectionDescriptorStore over a plain descriptor', () => {
  it('refuses a served `history: null` with ValidationError', async () => {
    // A malformed pointer off the wire is neither a governed projection nor a
    // client-written descriptor: the store refuses it with a typed error
    // before reading the log, rather than raising a `TypeError` or handing
    // the server's projection back as if the client had declared it.
    const served = {
      scheme: 'edv',
      epochs: [],
      history: null
    } as unknown as CollectionEncryption
    const { collection, fake } = fakeGovernedCollection({ encryption: served })
    const writer = await makeWriter()
    const store = logGovernedCollectionDescriptorStore({
      collection,
      resolveController: async () => writer.controller,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID
    })
    await expect(store.read()).rejects.toBeInstanceOf(ValidationError)
    expect(fake._state.logReads).toBe(0)
  })

  it('reads the point-state descriptor and writes the description', async () => {
    const reader = await makeReader()
    const initial: CollectionEncryption = {
      scheme: 'edv',
      epochs: [],
      currentEpoch: undefined
    }
    const { collection, fake } = fakeGovernedCollection({
      encryption: initial
    })
    const writer = await makeWriter()
    const store = logGovernedCollectionDescriptorStore({
      collection,
      resolveController: async () => writer.controller,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID
    })
    const current = await store.read()
    expect(current).toEqual({ descriptor: initial, etag: '"v0"' })
    const next = await addRecipient({
      store,
      recipient: reader.recipient,
      owner: { keyAgreementKey: reader.kak }
    }).catch(err => err)
    // No epochs yet: the primitive refuses, but the read path is the
    // description's, never the log's.
    expect(next).toBeInstanceOf(ValidationError)
    expect(fake._state.logReads).toBe(0)

    await store.replace({ ...initial, currentEpoch: 'e1' }, { ifMatch: '"v0"' })
    // The sibling fields ride along, the app attribution included: the
    // server's replace semantics would otherwise drop them on a key rotation.
    expect(fake._state.descriptionPuts).toEqual([
      {
        description: {
          name: 'Vault',
          backend: undefined,
          generator: { id: 'did:key:zApp', origin: 'https://app.example' },
          encryption: { ...initial, currentEpoch: 'e1' }
        },
        ifMatch: '"v0"'
      }
    ])
    expect(fake._state.logReads).toBe(0)
    expect(store.create).toBeUndefined()
  })

  it('reads a null encryption member as no descriptor', async () => {
    const { collection } = fakeGovernedCollection({
      encryption: null as unknown as CollectionEncryption
    })
    const writer = await makeWriter()
    const store = logGovernedCollectionDescriptorStore({
      collection,
      resolveController: async () => writer.controller,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID
    })
    expect(await store.read()).toBeNull()
  })
})

describe('logGovernedCollectionDescriptorStore over a governed collection', () => {
  it('creates the genesis, then reads the verified head as the descriptor', async () => {
    const { fake, pinStore, storeOptions, descriptor } = await governedFixture()
    expect(fake._state.logPuts).toEqual([{ ifNoneMatch: true }])
    const entries = fake._entries()
    expect(entries).toHaveLength(1)
    expect(genesisMethod(entries[0]!)).toBe(RESOURCE_LOG_METHOD)
    expect(entries[0]!.state.type).toBe(EPOCH_CONFIGURATION_STATE_TYPE)
    expect(entries[0]!.state).not.toHaveProperty('history')
    expect(await pinStore.read({ logId: LOG_ID })).toMatchObject({
      method: RESOURCE_LOG_METHOD,
      head: entries[0]!.versionId
    })

    const store = logGovernedCollectionDescriptorStore(storeOptions)
    const current = await store.read()
    expect(current?.etag).toBe('"v1"')
    expect(current?.descriptor).toEqual({
      ...toEpochConfigurationState(descriptor),
      history: { method: RESOURCE_LOG_METHOD, resource: LOG_URL }
    })
  })

  it('appends a signed entry on replace, pinned to the read etag', async () => {
    const { reader, writer, fake, pinStore, storeOptions } =
      await governedFixture()
    const other = await makeReader()
    const store = logGovernedCollectionDescriptorStore({
      ...storeOptions,
      signer: writer.signer
    })
    const next = await addRecipient({
      store,
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    expect(next.epochs?.[0]?.recipients).toHaveLength(2)
    expect(fake._state.logPuts).toEqual([
      { ifNoneMatch: true },
      { ifMatch: '"v1"' }
    ])
    const entries = fake._entries()
    expect(entries).toHaveLength(2)
    expect(entries[1]!.state).toEqual(toEpochConfigurationState(next))
    expect(await pinStore.read({ logId: LOG_ID })).toMatchObject({
      head: entries[1]!.versionId
    })
  })

  it('takes the governed write path on a replace right after its own create', async () => {
    const reader = await makeReader()
    const writer = await makeWriter()
    const { fake, collection } = fakeGovernedCollection()
    const store = logGovernedCollectionDescriptorStore({
      collection,
      resolveController: async () => writer.controller,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID,
      signer: writer.signer
    })
    // initRecipients reads (no descriptor yet) and then creates the genesis.
    const descriptor = await initRecipients({
      store,
      recipients: [reader.recipient]
    })
    // No read in between: the store must not act on the pre-create
    // description it observed, which named no governing log.
    await store.replace(descriptor, { ifMatch: '"v1"' })
    expect(fake._state.descriptionPuts).toEqual([])
    expect(fake._state.logPuts).toEqual([
      { ifNoneMatch: true },
      { ifMatch: '"v1"' }
    ])
    expect(fake._entries()).toHaveLength(2)
  })

  it('reports a projection behind the verified head as the port conflict class', async () => {
    const { reader, writer, fake, storeOptions } = await governedFixture()
    const other = await makeReader()
    await addRecipient({
      store: logGovernedCollectionDescriptorStore({
        ...storeOptions,
        signer: writer.signer
      }),
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    // The Description was read at the genesis head, then a concurrent append
    // landed before the log read: the projection equals the earlier entry's
    // state, a lost race rather than a forgery.
    const [genesis] = fake._entries()
    fake._state.projection = {
      ...(genesis!.state as unknown as CollectionEncryption),
      history: { method: RESOURCE_LOG_METHOD, resource: LOG_URL }
    }
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect(err).toBeInstanceOf(PreconditionFailedError)
    expect((err as Error).message).toMatch(/behind the verified head/)
  })

  it('forwards seal() to the generic store', async () => {
    const { writer, storeOptions } = await governedFixture()
    const store = logGovernedCollectionDescriptorStore({
      ...storeOptions,
      signer: writer.signer
    })
    // Nothing to seal against a one-version controller.
    expect(await store.seal()).toBe('noop')
    await expect(
      logGovernedCollectionDescriptorStore(storeOptions).seal()
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('reports a stale validator on replace as the port conflict class', async () => {
    const { writer, fake, storeOptions, descriptor } = await governedFixture()
    const store = logGovernedCollectionDescriptorStore({
      ...storeOptions,
      signer: writer.signer
    })
    await store.read()
    // A concurrent writer moved the log on: the held head is stale.
    fake._setEntries(fake._entries())
    const err = await store
      .replace(descriptor, { ifMatch: '"v1"' })
      .catch(err => err)
    expect(err).toBeInstanceOf(PreconditionFailedError)
    expect((err as Error).cause).toMatchObject({
      name: 'ResourceLogConflictError'
    })
  })

  it('is read-only without a signer', async () => {
    const { storeOptions, descriptor } = await governedFixture()
    const store = logGovernedCollectionDescriptorStore(storeOptions)
    expect(store.create).toBeUndefined()
    await store.read()
    await expect(
      store.replace(descriptor, { ifMatch: '"v1"' })
    ).rejects.toBeInstanceOf(ValidationError)
  })

  it('refuses a history.method mismatch before any fetch', async () => {
    const { fake, storeOptions } = await governedFixture()
    const readsBefore = fake._state.logReads
    fake._state.projection = {
      ...(await fake.describeWithEtag()).description.encryption!,
      history: { method: 'resource-log:9.9', resource: LOG_URL }
    }
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect((err as Error).message).toMatch(/resource-log:9\.9/)
    expect(fake._state.logReads).toBe(readsBefore)
  })

  it('refuses a history.resource that is not this collection log', async () => {
    const { fake, storeOptions } = await governedFixture()
    const readsBefore = fake._state.logReads
    fake._state.projection = {
      ...(await fake.describeWithEtag()).description.encryption!,
      history: {
        method: RESOURCE_LOG_METHOD,
        resource: 'https://pws.example/space/s1/key-map/vault.jsonl'
      }
    }
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect(fake._state.logReads).toBe(readsBefore)
  })

  it('refuses a projection that does not match the verified head', async () => {
    const { fake, storeOptions } = await governedFixture()
    const projection = (await fake.describeWithEtag()).description.encryption!
    fake._state.projection = { ...projection, currentEpoch: 'forged' }
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect((err as Error).message).toMatch(/does not match the verified head/)
  })

  it('refuses a projection whose log the collection does not serve', async () => {
    const { fake, storeOptions } = await governedFixture()
    fake._state.projection = (
      await fake.describeWithEtag()
    ).description.encryption!
    fake._state.body = undefined
    const err = await logGovernedCollectionDescriptorStore({
      ...storeOptions,
      pinStore: memoryResourceLogPinStore()
    })
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect((err as Error).message).toMatch(/serves none/)
  })

  it.each(['SomethingElse', OLD_STATE_TYPE])(
    'refuses a verified head whose state type is %s',
    async stateType => {
      const { fake, writer, storeOptions } = await governedFixture()
      fake._setEntries(
        await withForeignHead({
          entries: fake._entries(),
          controller: writer.controller,
          signer: writer.signer,
          stateType
        })
      )
      const err = await logGovernedCollectionDescriptorStore({
        ...storeOptions,
        pinStore: memoryResourceLogPinStore()
      })
        .read()
        .catch(err => err)
      expect((err as Error).name).toBe('ResourceLogIntegrityError')
      expect((err as Error).message).toContain(
        `"${stateType}", not "PwsEpochConfiguration"`
      )
      expect((err as Error).message).toMatch(/older client/)
    }
  )

  it('passes the library integrity refusal through unwrapped', async () => {
    const { fake, storeOptions } = await governedFixture()
    const [genesis] = fake._entries()
    // Swap the last character for a different one: `replace(/.$/, 'x')` is a
    // no-op on the ~1-in-58 freshly-minted versionId that already ends in `x`,
    // which leaves the entry untampered and the read succeeding.
    const tampered = genesis!.versionId.replace(/(.)$/, (last: string) =>
      last === 'x' ? 'y' : 'x'
    )
    fake._setEntries([{ ...genesis!, versionId: tampered }])
    const err = await logGovernedCollectionDescriptorStore({
      ...storeOptions,
      pinStore: memoryResourceLogPinStore()
    })
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    expect(err).not.toBeInstanceOf(PreconditionFailedError)
    expect(err).not.toBeInstanceOf(ValidationError)
  })

  it('passes the library continuity refusal through unwrapped', async () => {
    const { reader, writer, fake, storeOptions } = await governedFixture()
    const other = await makeReader()
    await addRecipient({
      store: logGovernedCollectionDescriptorStore({
        ...storeOptions,
        signer: writer.signer
      }),
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    // The pin now names the second entry; a host serving only the genesis is
    // a truncated log behind the pin.
    fake._setEntries(fake._entries().slice(0, 1))
    const err = await logGovernedCollectionDescriptorStore(storeOptions)
      .read()
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogContinuityError')
  })
})

describe('logGovernedDescriptorStore over any resource log', () => {
  async function genericFixture() {
    const reader = await makeReader()
    const writer = await makeWriter()
    const pinStore = memoryResourceLogPinStore()
    const log = memoryLogStore()
    const options = {
      log,
      resolveController: async () => writer.controller,
      pinStore,
      logId: 'space/s1/key-map/vault.jsonl'
    }
    return { reader, writer, pinStore, log, options }
  }

  it('reads null before genesis, creates, reads the head state, appends', async () => {
    const { reader, writer, pinStore, log, options } = await genericFixture()
    const store = logGovernedDescriptorStore({
      ...options,
      signer: writer.signer
    })
    expect(await store.read()).toBeNull()
    const descriptor = await initRecipients({
      store,
      recipients: [reader.recipient]
    })
    const current = await store.read()
    expect(current?.descriptor).toEqual(toEpochConfigurationState(descriptor))
    expect(current?.etag).toBe('v1')
    const other = await makeReader()
    const next = await addRecipient({
      store,
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    expect(log._getEntries()).toHaveLength(2)
    expect(log._getEntries()![1]!.state).toEqual(
      toEpochConfigurationState(next)
    )
    expect(await pinStore.read({ logId: options.logId })).toMatchObject({
      head: log._getEntries()![1]!.versionId
    })
    // Nothing to seal against a one-version controller.
    expect(await store.seal()).toBe('noop')
  })

  it('resumes a repeat read and a read-back from the last verified view', async () => {
    const { reader, writer, options } = await genericFixture()
    const counted = countingController(writer.controller)
    const store = logGovernedDescriptorStore({
      ...options,
      resolveController: async () => counted.controller,
      signer: writer.signer
    })
    await initRecipients({ store, recipients: [reader.recipient] })
    // The genesis: verified pre-write and on read-back.
    expect(counted.calls).toBe(2)
    await store.read()
    // The served log is the verified one: nothing to verify.
    expect(counted.calls).toBe(2)
    const other = await makeReader()
    await addRecipient({
      store,
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    // The recipient add reads (nothing new), then appends: the candidate
    // pre-write and the read-back, one entry each.
    expect(counted.calls).toBe(4)
    const fresh = logGovernedDescriptorStore({
      ...options,
      resolveController: async () => counted.controller,
      signer: writer.signer
    })
    const current = await fresh.read()
    // A fresh instance holds no view and verifies the two entries in full.
    expect(counted.calls).toBe(6)
    expect(current?.verified?.entries).toHaveLength(2)
  })

  it('verifies in full, and refuses a replace, under a view the held one is not a prefix of', async () => {
    const { reader, writer } = await genericFixture()
    const { keyMultibase } = writer.signer
    const versions = [
      { versionId: '1-a', keys: [keyMultibase] },
      { versionId: '2-b', keys: [keyMultibase] }
    ]
    const held = countingController(fakeController({ versions }))
    // A rewritten history: the held view's head version is still listed, but
    // no longer at its own index, so an index taken under the held view
    // names another version here.
    const shifted = countingController(
      fakeController({
        versions: [{ versionId: '0-z', keys: [keyMultibase] }, ...versions]
      })
    )
    let resolved = held
    const store = logGovernedDescriptorStore({
      log: memoryLogStore(),
      resolveController: async () => resolved.controller,
      pinStore: memoryResourceLogPinStore(),
      logId: 'space/s1/key-map/vault.jsonl',
      signer: writer.signer
    })
    const descriptor = await initRecipients({
      store,
      recipients: [reader.recipient]
    })
    const other = await makeReader()
    await addRecipient({
      store,
      recipient: other.recipient,
      owner: { keyAgreementKey: reader.kak }
    })
    resolved = shifted
    const current = await store.read()
    // The library declines to resume and verifies both entries in full.
    expect(shifted.calls).toBe(2)
    // The read verified under the shifted view, so a replace against it is
    // admitted; one against the held view is the port's conflict.
    resolved = held
    await expect(
      store.replace(descriptor, { ifMatch: current!.etag! })
    ).rejects.toThrow(PreconditionFailedError)
    await expect(
      store.replace(descriptor, { ifMatch: current!.etag! })
    ).rejects.toThrow('"2-b"')
  })

  it('refuses an unconditional replace', async () => {
    const { reader, writer, options } = await genericFixture()
    const store = logGovernedDescriptorStore({
      ...options,
      signer: writer.signer
    })
    const descriptor = await initRecipients({
      store,
      recipients: [reader.recipient]
    })
    await expect(store.replace(descriptor, {})).rejects.toThrow(
      NotSupportedError
    )
    await expect(store.replace(descriptor, {})).rejects.toThrow(
      /returned no ETag validator/
    )
  })

  it('translates a lost create race into the port conflict class', async () => {
    const { reader, writer, options } = await genericFixture()
    const winner = logGovernedDescriptorStore({
      ...options,
      signer: writer.signer
    })
    const descriptor = await initRecipients({
      store: winner,
      recipients: [reader.recipient]
    })
    const loser = logGovernedDescriptorStore({
      ...options,
      pinStore: memoryResourceLogPinStore(),
      signer: writer.signer
    })
    const err = await loser.create!(descriptor).catch(err => err)
    expect(err).toBeInstanceOf(PreconditionFailedError)
  })

  it('is read-only without a signer: no create, replace and seal refuse', async () => {
    const { reader, writer, options } = await genericFixture()
    const descriptor = await initRecipients({
      store: logGovernedDescriptorStore({ ...options, signer: writer.signer }),
      recipients: [reader.recipient]
    })
    const store = logGovernedDescriptorStore(options)
    expect(store.create).toBeUndefined()
    await expect(
      store.replace(descriptor, { ifMatch: 'v1' })
    ).rejects.toBeInstanceOf(ValidationError)
    await expect(store.seal()).rejects.toBeInstanceOf(ValidationError)
  })

  /**
   * A log signed under a controller that then removes a key, so a head from
   * before the removal needs sealing. `advance()` moves the view past the
   * removal; `appendForeignHead()` lands a signed head of the old state type
   * under the current view.
   */
  async function sealingFixture() {
    const { reader, writer, log, options } = await genericFixture()
    const departed = await makeWriter()
    const keys = [writer.signer.keyMultibase, departed.signer.keyMultibase]
    const beforeRemoval = fakeController({
      versions: [{ versionId: '1-a', keys }]
    })
    const afterRemoval = fakeController({
      versions: [
        { versionId: '1-a', keys },
        { versionId: '2-b', keys: [writer.signer.keyMultibase] }
      ]
    })
    let view = beforeRemoval
    const sealingOptions = {
      ...options,
      resolveController: async () => view,
      signer: writer.signer
    }
    await initRecipients({
      store: logGovernedDescriptorStore(sealingOptions),
      recipients: [reader.recipient]
    })
    return {
      log,
      sealingOptions,
      advance() {
        view = afterRemoval
      },
      async appendForeignHead() {
        log._setEntries(
          await withForeignHead({
            entries: log._getEntries()!,
            controller: view,
            signer: writer.signer
          })
        )
      },
      async expectSealRefused(
        store = logGovernedDescriptorStore(sealingOptions)
      ) {
        const err = await store.seal().catch(err => err)
        expect((err as Error).name).toBe('ResourceLogIntegrityError')
        expect(log._getEntries()).toHaveLength(2)
      }
    }
  }

  it('seals a log whose head is an epoch configuration', async () => {
    const { log, sealingOptions, advance } = await sealingFixture()
    advance()
    const store = logGovernedDescriptorStore(sealingOptions)
    expect(await store.seal()).toBe('sealed')
    expect(log._getEntries()).toHaveLength(2)
  })

  it('refuses to seal a head of another state type, appending nothing', async () => {
    const { advance, appendForeignHead, expectSealRefused } =
      await sealingFixture()
    await appendForeignHead()
    advance()
    await expectSealRefused()
  })

  it('refuses a head of another state type the sweep would call sealed', async () => {
    const { advance, appendForeignHead, expectSealRefused } =
      await sealingFixture()
    advance()
    await appendForeignHead()
    await expectSealRefused()
  })

  it('refuses to seal a head of another state type that landed after its read', async () => {
    const { sealingOptions, advance, appendForeignHead, expectSealRefused } =
      await sealingFixture()
    const store = logGovernedDescriptorStore(sealingOptions)
    await store.read()
    await appendForeignHead()
    advance()
    await expectSealRefused(store)
  })

  it('refuses to adopt a head of another state type from a lost create', async () => {
    const { reader, writer, log, options } = await genericFixture()
    const descriptor = await initRecipients({
      store: logGovernedDescriptorStore({ ...options, signer: writer.signer }),
      recipients: [reader.recipient]
    })
    log._setEntries(
      await withForeignHead({
        entries: log._getEntries()!,
        controller: writer.controller,
        signer: writer.signer
      })
    )
    const loser = logGovernedDescriptorStore({
      ...options,
      pinStore: memoryResourceLogPinStore(),
      signer: writer.signer
    })
    const err = await loser.create!(descriptor).catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
    // Nothing was held, so a later replace re-reads and meets the same refusal
    // rather than building on the adopted head.
    const replaced = await loser
      .replace(descriptor, { ifMatch: 'v2' })
      .catch(err => err)
    expect((replaced as Error).name).toBe('ResourceLogIntegrityError')
    expect(log._getEntries()).toHaveLength(2)
  })

  it('refuses a head of another state type on a replace read-back', async () => {
    const { reader, writer, log, options } = await genericFixture()
    const replacing = {
      ...options,
      signer: writer.signer,
      log: {
        ...log,
        // The acked append lands, then a foreign head lands before the
        // read-back confirms it.
        async append(
          entry: ResourceLogEntry,
          appendOptions: { ifMatch: string }
        ) {
          await log.append(entry, appendOptions)
          log._setEntries(
            await withForeignHead({
              entries: log._getEntries()!,
              controller: writer.controller,
              signer: writer.signer
            })
          )
        }
      }
    }
    const store = logGovernedDescriptorStore(replacing)
    await initRecipients({ store, recipients: [reader.recipient] })
    const current = await store.read()
    const err = await store
      .replace(current!.descriptor, { ifMatch: current!.etag! })
      .catch(err => err)
    expect((err as Error).name).toBe('ResourceLogIntegrityError')
  })
})
