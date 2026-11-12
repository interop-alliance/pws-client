/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * An in-memory stand-in for the Collection whose Description hosts an
 * encryption descriptor: just the `describeWithEtag` / `replaceDescription`
 * pair `addRecipient`, `removeRecipient` and `initRecipients` drive.
 */
import type { Collection, CollectionEncryption } from '../../src/index.js'

/**
 * Builds a descriptor holder. Reads return the current descriptor under a
 * version etag; every write replaces it, counts, and bumps the etag.
 *
 * @param initial {CollectionEncryption}   the descriptor the Description
 *   starts with
 * @param [collectionId] {string}   the Description's `id`, default `c`
 * @returns {{ collection: Collection; state: { encryption:
 *   CollectionEncryption; writes: number } }}   the holder cast as a
 *   `Collection`, and its mutable state
 */
export function memoryDescriptorHolder(
  initial: CollectionEncryption,
  collectionId = 'c'
): {
  collection: Collection
  state: { encryption: CollectionEncryption; writes: number }
} {
  const state = { encryption: initial, writes: 0 }
  const holder = {
    describeWithEtag: async () => ({
      description: {
        id: collectionId,
        type: ['Collection'],
        encryption: state.encryption
      },
      etag: `"v${state.writes + 1}"`
    }),
    replaceDescription: async (desc: { encryption?: CollectionEncryption }) => {
      state.writes += 1
      state.encryption = desc.encryption!
      return {
        description: { id: collectionId, type: ['Collection'] },
        etag: `"v${state.writes + 1}"`
      }
    }
  }
  return { collection: holder as unknown as Collection, state }
}
