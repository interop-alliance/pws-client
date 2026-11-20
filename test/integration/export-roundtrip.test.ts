/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: the three whole-space export shapes against a live PWS
 * server. Proves that `export()`, `exportBlob()`, and a fully-drained
 * `exportStream()` produce byte-identical tar archives for the same space, and
 * that `spaceB.import(await spaceA.exportBlob())` round-trips the resources.
 *
 * Requires a running server: set `TEST_SERVER_URL`. The suite skips when it is
 * unset, so a bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'

import type { PwsClient } from '../../src/index.js'
import type { Space } from '../../src/index.js'
import { drain } from '../helpers/bytes.js'
import { freshPwsClient } from '../helpers/liveClient.js'

const baseServerUrl = process.env.TEST_SERVER_URL
const describeLive = baseServerUrl ? describe : describe.skip

describeLive('whole-space export shapes (live server)', () => {
  let pws: PwsClient
  let source: Space

  beforeAll(async () => {
    pws = await freshPwsClient()
    source = await pws.createSpace({ name: 'Export Integration' })
    const notes = await source.createCollection({ id: 'notes', name: 'Notes' })
    await notes.put('first', { message: 'hello export' })
    await notes.put('second', { message: 'and again' })
  })

  afterAll(async () => {
    try {
      await source.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  it('export(), exportBlob(), and a drained exportStream() agree byte-for-byte', async () => {
    const fromExport = await source.export()
    const fromBlob = new Uint8Array(
      await (await source.exportBlob()).arrayBuffer()
    )
    const fromStream = await drain(await source.exportStream())

    // Every archive is non-empty and the three shapes carry identical bytes.
    expect(fromExport.byteLength).toBeGreaterThan(0)
    expect(fromBlob).toEqual(fromExport)
    expect(fromStream).toEqual(fromExport)
  })

  it('exportBlob() is typed application/x-tar and round-trips through import()', async () => {
    const blob = await source.exportBlob()
    expect(blob.type).toBe('application/x-tar')

    const target = await pws.createSpace({ name: 'Export Target' })
    try {
      const stats = await target.import(blob)
      expect(stats.collectionsCreated).toBeGreaterThan(0)
      expect(stats.resourcesCreated).toBeGreaterThanOrEqual(2)

      const copied = await target.collection('notes').get('first')
      expect(copied).toMatchObject({ message: 'hello export' })
    } finally {
      try {
        await target.delete()
      } catch {
        /* best-effort cleanup */
      }
    }
  })
})
