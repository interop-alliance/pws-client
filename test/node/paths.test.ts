/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the URL grammar beneath a Space. Every builder derives a URL
 * from a Space URL the server named, and the trailing-slash rules and
 * percent-encoding here must match the server's per-operation `allowedTarget`
 * exactly, since the zcap `invocationTarget` is derived from the request URL.
 * The convention under test: a trailing slash marks a container in canonical
 * form, everything else has none, and no two URLs differ only by a trailing
 * slash. The inverse grammar (`parseSpaceTarget`) and the chain-root reading
 * (`rootCapabilityTarget`, `spaceUrlOf`) are tested here too.
 */
import { describe, it, expect } from 'vitest'

import { ValidationError } from '../../src/index.js'
import type { IDelegatedZcap, IZcap } from '../../src/index.js'
import type { IRootZcap } from '../../src/paths.js'
import {
  baseServerUrlOf,
  canonicalBaseServerUrl,
  serviceDescriptionUrl,
  spaceUrlById,
  spacesRepositoryUrl,
  splitCollectionUrl
} from '../../src/paths.js'
import {
  canonicalSpaceUrl,
  spaceIdOfUrl,
  spaceMetaUrl,
  spaceExportUrl,
  spaceImportUrl,
  spaceBackendsUrl,
  registeredBackendUrl,
  spaceQuotasUrl,
  spacePolicyUrl,
  spaceLinksetUrl,
  spaceReplicasUrl,
  replicaRegistrationUrl,
  replicaStatusUrl,
  spaceRevocationUrl,
  collectionUrl,
  collectionPolicyUrl,
  collectionLinksetUrl,
  collectionBackendUrl,
  collectionQuotaUrl,
  collectionQueryUrl,
  collectionMetaUrl,
  collectionLogUrl,
  canonicalContainerUrl,
  resourceUrl,
  resourcePolicyUrl,
  resourceMetaUrl,
  resourceChunkUrl,
  resourceChunksUrl,
  parseSpaceTarget
} from '../../src/internal/paths.js'
import {
  rootCapabilityId,
  rootCapabilityTarget,
  spaceUrlOf
} from '../../src/internal/revoke.js'

const SPACE_URL = 'https://was.example/space/home/'

/**
 * Every builder, applied to one Space URL and fixed ids, so the whole grammar
 * can be checked at once.
 *
 * @param spaceUrl {string}
 * @returns {Record<string, string>}
 */
function everyUrl(spaceUrl: string): Record<string, string> {
  const inCollection = { spaceUrl, collectionId: 'docs' }
  const inResource = { ...inCollection, resourceId: 'note' }
  return {
    spaceMetaUrl: spaceMetaUrl({ spaceUrl }),
    spaceExportUrl: spaceExportUrl({ spaceUrl }),
    spaceImportUrl: spaceImportUrl({ spaceUrl }),
    spaceBackendsUrl: spaceBackendsUrl({ spaceUrl }),
    registeredBackendUrl: registeredBackendUrl({ spaceUrl, backendId: 'b1' }),
    spaceQuotasUrl: spaceQuotasUrl({ spaceUrl }),
    spacePolicyUrl: spacePolicyUrl({ spaceUrl }),
    spaceLinksetUrl: spaceLinksetUrl({ spaceUrl }),
    spaceReplicasUrl: spaceReplicasUrl({ spaceUrl }),
    replicaRegistrationUrl: replicaRegistrationUrl({
      spaceUrl,
      replicaId: 'r1'
    }),
    replicaStatusUrl: replicaStatusUrl({ spaceUrl, replicaId: 'r1' }),
    spaceRevocationUrl: spaceRevocationUrl({
      spaceUrl,
      capabilityId: 'urn:uuid:1'
    }),
    collectionUrl: collectionUrl(inCollection),
    collectionMetaUrl: collectionMetaUrl(inCollection),
    collectionLogUrl: collectionLogUrl(inCollection),
    collectionPolicyUrl: collectionPolicyUrl(inCollection),
    collectionLinksetUrl: collectionLinksetUrl(inCollection),
    collectionBackendUrl: collectionBackendUrl(inCollection),
    collectionQuotaUrl: collectionQuotaUrl(inCollection),
    collectionQueryUrl: collectionQueryUrl(inCollection),
    resourceUrl: resourceUrl(inResource),
    resourceMetaUrl: resourceMetaUrl(inResource),
    resourcePolicyUrl: resourcePolicyUrl(inResource),
    resourceChunkUrl: resourceChunkUrl({ ...inResource, chunkIndex: 0 }),
    resourceChunksUrl: resourceChunksUrl(inResource)
  }
}

describe('URL builders', () => {
  it('builds every URL beneath a canonical Space URL', () => {
    expect(everyUrl(SPACE_URL)).toEqual({
      spaceMetaUrl: 'https://was.example/space/home/meta',
      spaceExportUrl: 'https://was.example/space/home/export',
      spaceImportUrl: 'https://was.example/space/home/import',
      spaceBackendsUrl: 'https://was.example/space/home/backends',
      registeredBackendUrl: 'https://was.example/space/home/backends/b1',
      spaceQuotasUrl: 'https://was.example/space/home/quotas',
      spacePolicyUrl: 'https://was.example/space/home/policy',
      spaceLinksetUrl: 'https://was.example/space/home/linkset',
      spaceReplicasUrl: 'https://was.example/space/home/replicas',
      replicaRegistrationUrl: 'https://was.example/space/home/replicas/r1',
      replicaStatusUrl: 'https://was.example/space/home/replicas/r1/status',
      spaceRevocationUrl:
        'https://was.example/space/home/zcaps/revocations/urn%3Auuid%3A1',
      collectionUrl: 'https://was.example/space/home/docs/',
      collectionMetaUrl: 'https://was.example/space/home/docs/meta',
      collectionLogUrl: 'https://was.example/space/home/docs/meta/log',
      collectionPolicyUrl: 'https://was.example/space/home/docs/policy',
      collectionLinksetUrl: 'https://was.example/space/home/docs/linkset',
      collectionBackendUrl: 'https://was.example/space/home/docs/backend',
      collectionQuotaUrl: 'https://was.example/space/home/docs/quota',
      collectionQueryUrl: 'https://was.example/space/home/docs/query',
      resourceUrl: 'https://was.example/space/home/docs/note',
      resourceMetaUrl: 'https://was.example/space/home/docs/note/meta',
      resourcePolicyUrl: 'https://was.example/space/home/docs/note/policy',
      resourceChunkUrl: 'https://was.example/space/home/docs/note/chunks/0',
      resourceChunksUrl: 'https://was.example/space/home/docs/note/chunks/'
    })
  })

  it('keeps a path prefix the Space URL carries', () => {
    const spaceUrl = 'http://localhost:9787/was/v1/space/s/'
    for (const url of Object.values(everyUrl(spaceUrl))) {
      expect(url.startsWith(spaceUrl)).toBe(true)
    }
    expect(collectionUrl({ spaceUrl, collectionId: 'c' })).toBe(
      'http://localhost:9787/was/v1/space/s/c/'
    )
  })

  it('emits a chunk index verbatim', () => {
    expect(
      resourceChunkUrl({
        spaceUrl: SPACE_URL,
        collectionId: 'docs',
        resourceId: 'note',
        chunkIndex: 12
      })
    ).toBe('https://was.example/space/home/docs/note/chunks/12')
  })

  it('percent-encodes ids so they cannot break out of their slot', () => {
    expect(collectionUrl({ spaceUrl: SPACE_URL, collectionId: 'd?x' })).toBe(
      'https://was.example/space/home/d%3Fx/'
    )
    expect(
      resourceUrl({
        spaceUrl: SPACE_URL,
        collectionId: 'c/d',
        resourceId: 'r#1'
      })
    ).toBe('https://was.example/space/home/c%2Fd/r%231')
    expect(
      collectionQueryUrl({ spaceUrl: SPACE_URL, collectionId: 'a b' })
    ).toBe('https://was.example/space/home/a%20b/query')
    expect(
      resourceChunksUrl({
        spaceUrl: SPACE_URL,
        collectionId: 'c/d',
        resourceId: 'e#f'
      })
    ).toBe('https://was.example/space/home/c%2Fd/e%23f/chunks/')
    expect(
      replicaRegistrationUrl({ spaceUrl: SPACE_URL, replicaId: 'a/b' })
    ).toBe('https://was.example/space/home/replicas/a%2Fb')
    expect(
      registeredBackendUrl({ spaceUrl: SPACE_URL, backendId: 'g drive' })
    ).toBe('https://was.example/space/home/backends/g%20drive')
  })

  it('rejects a reserved id in a collection or resource slot', () => {
    // `collectionUrl` of `policy` would be byte-identical to the space policy
    // URL, and `resourceUrl` of `meta` to the collection metadata URL.
    expect(() =>
      collectionUrl({ spaceUrl: SPACE_URL, collectionId: 'policy' })
    ).toThrow(ValidationError)
    expect(() =>
      collectionMetaUrl({ spaceUrl: SPACE_URL, collectionId: 'meta' })
    ).toThrow(ValidationError)
    expect(() =>
      resourceUrl({
        spaceUrl: SPACE_URL,
        collectionId: 'c',
        resourceId: 'meta'
      })
    ).toThrow(ValidationError)
    expect(() =>
      resourceMetaUrl({
        spaceUrl: SPACE_URL,
        collectionId: 'c',
        resourceId: 'policy'
      })
    ).toThrow(ValidationError)
  })

  it('rejects dot-segment ids, which URL resolution would collapse', () => {
    // `encodeURIComponent` leaves `.`/`..` intact, and `new URL()` collapses
    // them -- `{spaceUrl}c/.` is the collection items endpoint and
    // `{spaceUrl}c/..` the space -- so a delete would target the wrong thing.
    expect(() =>
      resourceUrl({ spaceUrl: SPACE_URL, collectionId: 'c', resourceId: '.' })
    ).toThrow(ValidationError)
    expect(() =>
      resourceUrl({ spaceUrl: SPACE_URL, collectionId: 'c', resourceId: '..' })
    ).toThrow(ValidationError)
    expect(() =>
      collectionUrl({ spaceUrl: SPACE_URL, collectionId: '.' })
    ).toThrow(ValidationError)
    expect(() =>
      replicaRegistrationUrl({ spaceUrl: SPACE_URL, replicaId: '..' })
    ).toThrow(ValidationError)
  })

  it('rejects an empty id, which collapses into the parent endpoint', () => {
    expect(() =>
      resourceUrl({ spaceUrl: SPACE_URL, collectionId: 'c', resourceId: '' })
    ).toThrow(ValidationError)
    expect(() =>
      collectionUrl({ spaceUrl: SPACE_URL, collectionId: '' })
    ).toThrow(ValidationError)
    expect(() =>
      registeredBackendUrl({ spaceUrl: SPACE_URL, backendId: '' })
    ).toThrow(ValidationError)
  })

  it('canonicalizes the Space URL before joining onto it', () => {
    // A missing trailing slash, a run of them, an upper-case host and a
    // default port all name the same Space, so they yield the same URLs.
    const canonical = everyUrl(SPACE_URL)
    for (const spaceUrl of [
      'https://was.example/space/home',
      'https://was.example/space/home///',
      'https://WAS.Example/space/home/',
      'https://was.example:443/space/home/'
    ]) {
      expect(everyUrl(spaceUrl)).toEqual(canonical)
    }
  })

  it('throws ValidationError when the Space URL is not one', () => {
    for (const spaceUrl of [
      'not a url',
      '/space/home/',
      'ftp://was.example/space/home/',
      'https://was.example/space/home/?q=1',
      'https://was.example/space/home/#f',
      'https://was.example/space//home/'
    ]) {
      expect(() => spaceMetaUrl({ spaceUrl })).toThrow(ValidationError)
      expect(() => collectionUrl({ spaceUrl, collectionId: 'c' })).toThrow(
        ValidationError
      )
      expect(() =>
        resourceUrl({ spaceUrl, collectionId: 'c', resourceId: 'r' })
      ).toThrow(ValidationError)
    }
  })
})

describe('the trailing-slash convention', () => {
  /**
   * A capability's `invocationTarget` covers its URL and everything under it
   * by prefix, so two URLs differing only by a trailing slash could not be
   * granted separately; the server's route table has none, and neither may
   * the builders.
   */
  const urls = { space: SPACE_URL, ...everyUrl(SPACE_URL) }

  it('produces no two URLs that differ only by a trailing slash', () => {
    const collisions = Object.entries(urls).filter(([, url]) =>
      Object.values(urls).some(other => other !== url && `${other}/` === url)
    )
    expect(collisions).toEqual([])
  })

  it('ends every container URL with a slash and no other URL', () => {
    const slashed = Object.entries(urls)
      .filter(([, url]) => url.endsWith('/'))
      .map(([name]) => name)
    expect(new Set(slashed)).toEqual(
      new Set(['space', 'collectionUrl', 'resourceChunksUrl'])
    )
  })
})

describe('canonicalContainerUrl', () => {
  it('adds the trailing slash to a bare collection URL, and keeps one', () => {
    expect(canonicalContainerUrl('https://was.example/space/s/c')).toBe(
      'https://was.example/space/s/c/'
    )
    expect(canonicalContainerUrl('https://was.example/space/s/c/')).toBe(
      'https://was.example/space/s/c/'
    )
  })
})

describe('canonicalSpaceUrl', () => {
  it('returns a canonical Space URL unchanged', () => {
    expect(canonicalSpaceUrl(SPACE_URL)).toBe(SPACE_URL)
    expect(canonicalSpaceUrl('http://localhost:9787/was/v1/space/s/')).toBe(
      'http://localhost:9787/was/v1/space/s/'
    )
  })

  it('adds a missing trailing slash and collapses a run of them', () => {
    expect(canonicalSpaceUrl('https://was.example/space/home')).toBe(SPACE_URL)
    expect(canonicalSpaceUrl('https://was.example/space/home//')).toBe(
      SPACE_URL
    )
  })

  it('lower-cases the host and drops a default port', () => {
    expect(canonicalSpaceUrl('https://WAS.example:443/space/home/')).toBe(
      SPACE_URL
    )
    expect(canonicalSpaceUrl('http://Localhost:80/space/home')).toBe(
      'http://localhost/space/home/'
    )
    // A non-default port is part of the origin and stays.
    expect(canonicalSpaceUrl('http://localhost:9787/space/home')).toBe(
      'http://localhost:9787/space/home/'
    )
  })

  it('keeps percent-encoded segments as they are', () => {
    expect(canonicalSpaceUrl('https://was.example/space/a%20b')).toBe(
      'https://was.example/space/a%20b/'
    )
  })

  it('throws ValidationError for a URL that cannot be a Space URL', () => {
    for (const spaceUrl of [
      'not a url',
      '/space/home/',
      'ftp://was.example/space/home/',
      'file:///space/home/',
      'https://was.example/space/home/?q=1',
      'https://was.example/space/home/#top',
      'https://was.example//space/home/',
      'https://was.example/space//home/'
    ]) {
      expect(() => canonicalSpaceUrl(spaceUrl)).toThrow(ValidationError)
    }
  })
})

describe('spaceIdOfUrl', () => {
  it('reads the last path segment of the Space URL', () => {
    expect(spaceIdOfUrl(SPACE_URL)).toBe('home')
    expect(spaceIdOfUrl('https://was.example/space/home')).toBe('home')
    expect(spaceIdOfUrl('http://localhost:9787/was/v1/space/s///')).toBe('s')
  })

  it('percent-decodes the segment', () => {
    expect(spaceIdOfUrl('https://was.example/space/a%20b%2Fc/')).toBe('a b/c')
  })

  it('throws ValidationError for a malformed percent escape', () => {
    expect(() => spaceIdOfUrl('https://was.example/space/%ff/')).toThrow(
      ValidationError
    )
  })

  it('throws ValidationError for a URL that is not a Space URL', () => {
    expect(() => spaceIdOfUrl('https://was.example/')).toThrow(ValidationError)
    expect(() => spaceIdOfUrl('not a url')).toThrow(ValidationError)
  })
})

describe('parseSpaceTarget', () => {
  const spaceUrl = SPACE_URL

  /**
   * @param target {string}
   * @returns {ReturnType<typeof parseSpaceTarget>}
   */
  function parse(target: string): ReturnType<typeof parseSpaceTarget> {
    return parseSpaceTarget({ spaceUrl, target })
  }

  it('classifies the Space itself in its slash and bare forms', () => {
    expect(parse('https://was.example/space/home/')).toEqual({ kind: 'space' })
    expect(parse('https://was.example/space/home')).toEqual({ kind: 'space' })
  })

  it('classifies a Collection in its slash and bare forms', () => {
    // The builders emit only the canonical trailing-slash form, but the
    // targets parsed here come from delegated capabilities minted elsewhere,
    // and both forms name the same container.
    for (const target of [
      'https://was.example/space/home/docs/',
      'https://was.example/space/home/docs'
    ]) {
      expect(parse(target)).toEqual({
        kind: 'collection',
        collectionId: 'docs'
      })
    }
  })

  it('classifies a Resource', () => {
    expect(parse('https://was.example/space/home/docs/note')).toEqual({
      kind: 'resource',
      collectionId: 'docs',
      resourceId: 'note'
    })
  })

  it('classifies a space-level sub-endpoint as a sub-resource', () => {
    expect(parse('https://was.example/space/home/policy')).toEqual({
      kind: 'sub-resource',
      segments: ['policy']
    })
    expect(parse('https://was.example/space/home/backends/x')).toEqual({
      kind: 'sub-resource',
      segments: ['backends', 'x']
    })
    // The Space Metadata object sits at the Collection-id position, so `meta`
    // directly under a Space is a space-level sub-endpoint rather than a
    // Collection named `meta`.
    expect(parse('https://was.example/space/home/meta')).toEqual({
      kind: 'sub-resource',
      segments: ['meta']
    })
    expect(
      parse('https://was.example/space/home/zcaps/revocations/urn%3Ax')
    ).toEqual({
      kind: 'sub-resource',
      segments: ['zcaps', 'revocations', 'urn:x']
    })
  })

  it('classifies a collection-level sub-endpoint as a sub-resource', () => {
    expect(parse('https://was.example/space/home/c/backend')).toEqual({
      kind: 'sub-resource',
      segments: ['c', 'backend']
    })
    expect(parse('https://was.example/space/home/c/meta')).toEqual({
      kind: 'sub-resource',
      segments: ['c', 'meta']
    })
  })

  it('classifies a resource-level sub-endpoint as a sub-resource', () => {
    expect(parse('https://was.example/space/home/c/r/meta')).toEqual({
      kind: 'sub-resource',
      segments: ['c', 'r', 'meta']
    })
    expect(parse('https://was.example/space/home/c/r/chunks/0')).toEqual({
      kind: 'sub-resource',
      segments: ['c', 'r', 'chunks', '0']
    })
    expect(parse('https://was.example/space/home/c/r/chunks/')).toEqual({
      kind: 'sub-resource',
      segments: ['c', 'r', 'chunks']
    })
  })

  it('percent-decodes each segment (the builders re-encode them)', () => {
    expect(parse('https://was.example/space/home/a%20b/c%2Fd')).toEqual({
      kind: 'resource',
      collectionId: 'a b',
      resourceId: 'c/d'
    })
  })

  it('round-trips every builder output', () => {
    const collection = collectionUrl({ spaceUrl, collectionId: 'a b' })
    const resource = resourceUrl({
      spaceUrl,
      collectionId: 'a b',
      resourceId: 'r#1'
    })
    expect(parse(collection)).toEqual({
      kind: 'collection',
      collectionId: 'a b'
    })
    expect(parse(resource)).toEqual({
      kind: 'resource',
      collectionId: 'a b',
      resourceId: 'r#1'
    })
  })

  it('returns null for a target that is not beneath the Space', () => {
    for (const target of [
      'https://other.example/space/home/docs/',
      'http://was.example/space/home/docs/',
      'https://was.example/space/home2/docs/',
      'https://was.example/space/',
      'https://was.example/other/home/docs/',
      'https://was.example/space/home/docs/?q=1',
      'https://was.example/space/home/docs/#f',
      'https://was.example/space/home/%ff',
      'https://was.example/space/home/c/%c3%28',
      '/space/home/docs/',
      'not a url'
    ]) {
      expect(parse(target)).toBeNull()
    }
  })

  it('returns null when the Space URL is not one', () => {
    expect(
      parseSpaceTarget({
        spaceUrl: 'not a url',
        target: 'https://was.example/space/home/'
      })
    ).toBeNull()
  })

  it('matches when either URL is in a non-canonical serialization', () => {
    for (const nonCanonical of [
      'https://was.example/space/home',
      'https://WAS.example:443/space/home//'
    ]) {
      expect(
        parseSpaceTarget({
          spaceUrl: nonCanonical,
          target: 'https://was.example/space/home/docs/'
        })
      ).toEqual({ kind: 'collection', collectionId: 'docs' })
    }
    expect(
      parseSpaceTarget({
        spaceUrl,
        target: 'https://WAS.example:443/space/home/docs/'
      })
    ).toEqual({ kind: 'collection', collectionId: 'docs' })
  })

  it('classifies beneath a Space whose URL carries a path prefix', () => {
    expect(
      parseSpaceTarget({
        spaceUrl: 'http://localhost:9787/was/v1/space/s/',
        target: 'http://localhost:9787/was/v1/space/s/c/r'
      })
    ).toEqual({ kind: 'resource', collectionId: 'c', resourceId: 'r' })
  })
})

describe('rootCapabilityId / rootCapabilityTarget', () => {
  it('round-trips a target through its root capability id', () => {
    for (const target of [
      SPACE_URL,
      'http://localhost:3000/space/s/c/r',
      'https://was.example/space/a%20b/'
    ]) {
      const id = rootCapabilityId(target)
      expect(id).toBe(`urn:zcap:root:${encodeURIComponent(target)}`)
      expect(rootCapabilityTarget(id)).toBe(target)
    }
  })

  it('returns null for an id that is not a root capability id', () => {
    expect(rootCapabilityTarget('urn:uuid:5f1a')).toBeNull()
    expect(rootCapabilityTarget(SPACE_URL)).toBeNull()
    // A malformed percent escape in the encoded target.
    expect(rootCapabilityTarget('urn:zcap:root:%ff')).toBeNull()
  })
})

describe('spaceUrlOf', () => {
  const rootId = rootCapabilityId(SPACE_URL)

  /**
   * A delegated capability fixture with the given chain fields.
   *
   * @param fields {object}
   * @returns {IDelegatedZcap}
   */
  function delegated(fields: Record<string, unknown>): IDelegatedZcap {
    return {
      '@context': ['https://w3id.org/zcap/v1'],
      id: 'urn:uuid:child',
      controller: 'did:example:bob',
      invocationTarget: `${SPACE_URL}docs/`,
      expires: '2099-01-01T00:00:00Z',
      allowedAction: ['GET'],
      ...fields
    } as unknown as IDelegatedZcap
  }

  it('reads the Space off the first entry of proof.capabilityChain', () => {
    // A two-level delegation: the parent is another delegated capability, so
    // only the chain names the root.
    const zcap = delegated({
      parentCapability: 'urn:uuid:parent',
      proof: { capabilityChain: [rootId, 'urn:uuid:parent'] }
    })
    expect(spaceUrlOf(zcap)).toBe(SPACE_URL)
  })

  it('reads the chain off the first proof when there are several', () => {
    const zcap = delegated({
      parentCapability: 'urn:uuid:parent',
      proof: [
        { capabilityChain: [rootId, 'urn:uuid:parent'] },
        { capabilityChain: ['urn:zcap:root:elsewhere'] }
      ]
    })
    expect(spaceUrlOf(zcap)).toBe(SPACE_URL)
  })

  it('finds the delegation proof behind an assertion proof', () => {
    const zcap = delegated({
      parentCapability: 'urn:uuid:parent',
      proof: [
        { type: 'DataIntegrityProof', proofPurpose: 'assertionMethod' },
        { capabilityChain: [rootId, 'urn:uuid:parent'] }
      ]
    })
    expect(spaceUrlOf(zcap)).toBe(SPACE_URL)
  })

  it('reads a root target that could be a Space as the Space', () => {
    // A Collection URL has the shape of a Space URL, so a chain rooted at a
    // Collection is read as rooted at a Space of that URL: the server, which
    // knows its hierarchy, is the authority. This is the documented boundary.
    const collectionRoot = rootCapabilityId(`${SPACE_URL}docs/`)
    expect(spaceUrlOf(delegated({ parentCapability: collectionRoot }))).toBe(
      `${SPACE_URL}docs/`
    )
  })

  it('reads the Space off a string parentCapability (single-level)', () => {
    expect(spaceUrlOf(delegated({ parentCapability: rootId }))).toBe(SPACE_URL)
  })

  it("reads the Space off a root capability's own id", () => {
    const root: IRootZcap = {
      '@context': 'https://w3id.org/zcap/v1',
      id: rootId,
      invocationTarget: SPACE_URL,
      controller: 'did:example:alice'
    }
    expect(spaceUrlOf(root as IZcap)).toBe(SPACE_URL)
  })

  it('canonicalizes the Space URL the root id names', () => {
    for (const named of [
      'https://was.example/space/home',
      'https://WAS.example:443/space/home//'
    ]) {
      expect(
        spaceUrlOf(delegated({ parentCapability: rootCapabilityId(named) }))
      ).toBe(SPACE_URL)
    }
  })

  it('throws ValidationError when the chain does not start at a root id', () => {
    expect(() =>
      spaceUrlOf(delegated({ parentCapability: 'urn:uuid:parent' }))
    ).toThrow(ValidationError)
    expect(() =>
      spaceUrlOf(
        delegated({
          parentCapability: 'urn:uuid:parent',
          proof: { capabilityChain: ['urn:uuid:other'] }
        })
      )
    ).toThrow(/not rooted in a Space/)
  })

  it('throws ValidationError when the root names a non-Space URL', () => {
    for (const target of [
      'https://was.example/space/home/?q=1',
      'did:example:alice'
    ]) {
      expect(() =>
        spaceUrlOf(delegated({ parentCapability: rootCapabilityId(target) }))
      ).toThrow(ValidationError)
    }
    expect(() =>
      spaceUrlOf(
        delegated({ parentCapability: rootCapabilityId('did:example:x') })
      )
    ).toThrow(/not a Space URL/)
  })
})

describe('the ./paths subpath barrel', () => {
  it('re-exports the builders, the inverse grammar, the reserved-segment predicates, and the root zcap', async () => {
    const barrel = await import('../../src/paths.js')

    expect(Object.keys(barrel).sort()).toEqual(
      [
        'baseServerUrlOf',
        'canonicalBaseServerUrl',
        'canonicalSpaceUrl',
        'collectionLogUrl',
        'collectionMetaUrl',
        'collectionQueryUrl',
        'collectionUrl',
        'isReservedCollectionId',
        'isReservedResourceId',
        'parseSpaceTarget',
        'replicaRegistrationUrl',
        'resourceMetaUrl',
        'resourceUrl',
        'rootCapability',
        'rootCapabilityId',
        'rootCapabilityTarget',
        'serviceDescriptionUrl',
        'spaceIdOfUrl',
        'spaceMetaUrl',
        'spaceReplicasUrl',
        'spaceUrlById',
        'spaceUrlOf',
        'spacesRepositoryUrl',
        'splitCollectionUrl'
      ].sort()
    )
    // Same functions as the internal modules, not re-implementations.
    expect(barrel.resourceMetaUrl).toBe(resourceMetaUrl)
    expect(barrel.collectionMetaUrl).toBe(collectionMetaUrl)
    expect(barrel.parseSpaceTarget).toBe(parseSpaceTarget)
    expect(barrel.spaceUrlOf).toBe(spaceUrlOf)
    expect(barrel.rootCapabilityTarget).toBe(rootCapabilityTarget)
    expect(barrel.spaceReplicasUrl).toBe(spaceReplicasUrl)
    expect(barrel.replicaRegistrationUrl).toBe(replicaRegistrationUrl)
  })

  it('forms the replicas route and a registration beneath it', async () => {
    const barrel = await import('../../src/paths.js')

    // The replicas-route grant's `invocationTarget`: the bare path, no
    // trailing slash.
    expect(barrel.spaceReplicasUrl({ spaceUrl: SPACE_URL })).toBe(
      'https://was.example/space/home/replicas'
    )
    expect(
      barrel.replicaRegistrationUrl({ spaceUrl: SPACE_URL, replicaId: 'r 1' })
    ).toBe('https://was.example/space/home/replicas/r%201')
  })

  it('mints the root capability id and its object form', async () => {
    const { rootCapability, rootCapabilityId: barrelRootId } =
      await import('../../src/paths.js')
    const target = 'http://localhost:3000/space/s/c/r'

    expect(barrelRootId(target)).toBe(
      `urn:zcap:root:${encodeURIComponent(target)}`
    )
    // `IRootZcap` -- `rootCapability`'s return type -- is reachable from the
    // same entry as the function, so a caller can annotate what it holds.
    const root: IRootZcap = rootCapability({
      target,
      controller: 'did:key:zAlice'
    })
    expect(root).toEqual({
      '@context': 'https://w3id.org/zcap/v1',
      id: barrelRootId(target),
      invocationTarget: target,
      controller: 'did:key:zAlice'
    })
  })
})

describe('the server layout under a base server URL', () => {
  const bases = ['https://h/', 'https://h/pws/']

  it('canonicalBaseServerUrl supplies the trailing slash and normalizes', () => {
    expect(canonicalBaseServerUrl('https://h/pws')).toBe('https://h/pws/')
    expect(canonicalBaseServerUrl('https://H:443')).toBe('https://h/')
    for (const url of ['nope', 'ftp://h/', 'https://h/?q=1', 'https://h/#f']) {
      expect(() => canonicalBaseServerUrl(url)).toThrow(ValidationError)
    }
  })

  it('builds the service description and Spaces Repository URLs', () => {
    expect(serviceDescriptionUrl({ baseServerUrl: 'https://h/pws/' })).toBe(
      'https://h/pws/service'
    )
    expect(spacesRepositoryUrl({ baseServerUrl: 'https://h/' })).toBe(
      'https://h/spaces/'
    )
  })

  it('spaceUrlById works under an origin-root and a sub-path base', () => {
    expect(spaceUrlById({ baseServerUrl: 'https://h/', spaceId: 's' })).toBe(
      'https://h/space/s/'
    )
    expect(
      spaceUrlById({ baseServerUrl: 'https://h/pws/', spaceId: 's' })
    ).toBe('https://h/pws/space/s/')
  })

  it('spaceUrlById percent-encodes the id and rejects empty and dot ids', () => {
    expect(spaceUrlById({ baseServerUrl: 'https://h/', spaceId: 'a b' })).toBe(
      'https://h/space/a%20b/'
    )
    for (const spaceId of ['', '.', '..']) {
      expect(() =>
        spaceUrlById({ baseServerUrl: 'https://h/', spaceId })
      ).toThrow(ValidationError)
    }
  })

  it('baseServerUrlOf round-trips with each builder, for both bases', () => {
    for (const baseServerUrl of bases) {
      expect(baseServerUrlOf(serviceDescriptionUrl({ baseServerUrl }))).toBe(
        baseServerUrl
      )
      expect(baseServerUrlOf(spacesRepositoryUrl({ baseServerUrl }))).toBe(
        baseServerUrl
      )
      expect(
        baseServerUrlOf(spaceUrlById({ baseServerUrl, spaceId: 's' }))
      ).toBe(baseServerUrl)
    }
  })

  it('baseServerUrlOf accepts the slashless Spaces and Space forms', () => {
    expect(baseServerUrlOf('https://h/pws/spaces')).toBe('https://h/pws/')
    expect(baseServerUrlOf('https://h/pws/space/s')).toBe('https://h/pws/')
  })

  it('baseServerUrlOf reads a Space whose id is spaces or service as a Space', () => {
    expect(baseServerUrlOf('https://h/pws/space/spaces/')).toBe(
      'https://h/pws/'
    )
    expect(baseServerUrlOf('https://h/pws/space/service')).toBe(
      'https://h/pws/'
    )
  })

  it('baseServerUrlOf rejects Collection, Resource, origin-root and query URLs', () => {
    for (const url of [
      'https://h/pws/space/s/posts/',
      'https://h/pws/space/s/posts/r1',
      'https://h/',
      'https://h/pws/spaces/?q=1'
    ]) {
      expect(() => baseServerUrlOf(url)).toThrow(ValidationError)
    }
  })

  it('splitCollectionUrl splits the Space URL from the Collection id', () => {
    expect(splitCollectionUrl('https://h/pws/space/s/posts/')).toEqual({
      spaceUrl: 'https://h/pws/space/s/',
      collectionId: 'posts'
    })
    expect(splitCollectionUrl('https://alice.example/posts/')).toEqual({
      spaceUrl: 'https://alice.example/',
      collectionId: 'posts'
    })
    expect(splitCollectionUrl('https://h/pws/space/s/posts')).toEqual({
      spaceUrl: 'https://h/pws/space/s/',
      collectionId: 'posts'
    })
    expect(splitCollectionUrl('https://h/space/s/a%20b/').collectionId).toBe(
      'a b'
    )
    expect(() => splitCollectionUrl('https://alice.example/')).toThrow(
      ValidationError
    )
  })

  it('canonicalSpaceUrl accepts an origin root, which has no id', () => {
    expect(canonicalSpaceUrl('https://alice.example')).toBe(
      'https://alice.example/'
    )
    expect(() => spaceIdOfUrl('https://alice.example/')).toThrow(
      ValidationError
    )
  })

  it('reserves service, spaces and space as Collection ids at an origin root only', () => {
    for (const collectionId of ['service', 'spaces', 'space']) {
      expect(() =>
        collectionUrl({ spaceUrl: 'https://alice.example/', collectionId })
      ).toThrow(ValidationError)
      expect(
        collectionUrl({ spaceUrl: 'https://h/space/s/', collectionId })
      ).toBe(`https://h/space/s/${collectionId}/`)
      // The inverse grammar agrees: at an origin root the segment is a
      // sub-resource, elsewhere a Collection.
      expect(
        parseSpaceTarget({
          spaceUrl: 'https://alice.example/',
          target: `https://alice.example/${collectionId}`
        })
      ).toEqual({ kind: 'sub-resource', segments: [collectionId] })
      expect(
        parseSpaceTarget({
          spaceUrl: 'https://h/space/s/',
          target: `https://h/space/s/${collectionId}/`
        })
      ).toEqual({ kind: 'collection', collectionId })
    }
  })
})
