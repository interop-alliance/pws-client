/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Browser-side fixture for the chunked-decrypt Playwright test. Everything
 * here runs inside Chromium (the Vite dev server transforms it on the fly):
 * it writes one chunked encrypted document to an in-memory backend, then
 * decrypts it through a `chunkSource` that fails in a chosen way, and returns
 * the name of the error the decrypt rejected with. Only a real browser can
 * show that buffering the decrypt stream keeps that error (see
 * `streamToBlob`).
 */
import type { IEDVChunk } from '@interop/data-integrity-core'

import type { ChunkedWrite, ResourceCodec } from '../../../src/index.js'
import type { Json } from '../../../src/sync/index.js'
import type { ChunkSource } from '../../../src/edv/core.js'
import {
  createEdvDocCipher,
  createEdvEncryption
} from '../../../src/edv/index.js'
import { blobBytes } from '../../../src/internal/blob.js'
import { flipFirst } from '../../helpers/bytes.js'
import { memoryBackend } from '../../helpers/codec.js'
import { makeReaderWithDescriptor } from '../../helpers/readerKeys.js'

/**
 * What `decryptChunked` reports: the byte count read back, or the rejection's
 * `name` and `message`.
 */
export type Outcome =
  { ok: true; bytes: number } | { name: string; message: string }

/**
 * Writes a 64-byte blob as a chunked document, then decrypts it with a
 * `chunkSource` altered by `failure`, and reports what happened.
 *
 * @param failure {'none' | 'missing' | 'tampered'}   serve every chunk, drop
 *   chunk 1, or flip a byte of chunk 1's ciphertext
 * @returns {Promise<Outcome>}
 */
export async function decryptChunked(
  failure: 'none' | 'missing' | 'tampered'
): Promise<Outcome> {
  const { encryption, ...keys } = await makeReaderWithDescriptor()
  const codec = (await createEdvEncryption({
    resolveKeys: async () => keys,
    maxBlobBytes: 16,
    chunkSize: 24
  }).codecFor({
    spaceUrl: 'https://was.example/space/s/',
    collectionId: 'c',
    scheme: 'edv',
    encryption
  })) as ResourceCodec
  const backend = memoryBackend()
  const readJson = <T>(path: string): T =>
    JSON.parse(new TextDecoder().decode(backend.store.get(path))) as T
  const blob = new Uint8Array(64).map((_value, index) => (index * 7) % 251)
  const plan = (await codec.encode({
    data: blob,
    contentType: 'application/octet-stream'
  })) as ChunkedWrite
  await plan.execute(backend.context)
  const envelope = readJson<Json>(`/space/s/c/${plan.id}`)

  const chunkSource: ChunkSource = async ({ docId, chunkIndex }) => {
    const path = `/space/s/c/${docId}/chunks/${chunkIndex}`
    if (!backend.store.has(path)) {
      return undefined
    }
    if (chunkIndex === 1 && failure === 'missing') {
      return undefined
    }
    const chunk = readJson<IEDVChunk>(path)
    if (chunkIndex === 1 && failure === 'tampered') {
      chunk.jwe.ciphertext = flipFirst(chunk.jwe.ciphertext as string)
    }
    return chunk
  }
  const cipher = await createEdvDocCipher({
    ...keys,
    collectionId: 'c',
    encryption
  })
  try {
    const decrypted = (await cipher.decrypt({
      id: plan.id,
      envelope,
      chunkSource
    })) as Blob
    return { ok: true, bytes: (await blobBytes(decrypted)).byteLength }
  } catch (err) {
    const { name, message } = err as Error
    return { name, message }
  }
}
