/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Portable `Blob` reads and writes: reading a `Blob` to text or bytes,
 * building a `Blob` from bytes, and the conversions between in-hand bytes and
 * a byte stream.
 *
 * A `Blob` in a browser or in Node implements `text()` and `arrayBuffer()`, so
 * reading one is a single await. React Native's built-in `Blob` implements
 * neither -- calling them throws `TypeError: undefined is not a function` --
 * but RN does provide a global `FileReader` with `readAsText` /
 * `readAsArrayBuffer`, which reads its own `Blob` type. That asymmetry is
 * invisible in tests (they run on Node, where the native methods exist) and in
 * the browser wallet, so every `Blob` read in this library goes through the two
 * helpers here rather than calling the native methods directly.
 *
 * Each helper prefers the native method when it is present and falls back to a
 * `FileReader` otherwise. The fallback is Promise-wrapped by hand because
 * `FileReader` is event-based: it resolves on `onload` with `reader.result` and
 * rejects on `onerror` with the reader's own error.
 *
 * Building a `Blob` has the mirror-image asymmetry: React Native's `Blob`
 * constructor refuses an `ArrayBuffer` or a typed array, so `bytesToBlob`
 * falls back to a `data:` URL fetch there.
 */
import { base64 } from '@scure/base'

/**
 * The subset of the event-based `FileReader` surface the fallback drives,
 * declared structurally so the helpers do not depend on the DOM `FileReader`
 * constructor's exact type (React Native's implementation is its own class).
 */
interface FileReaderLike {
  result: unknown
  error: unknown
  onload: (() => void) | null
  onerror: (() => void) | null
  readAsText(blob: Blob): void
  readAsArrayBuffer(blob: Blob): void
}

/**
 * The global `FileReader` constructor, or `undefined` where the runtime has
 * none (plain Node, which needs no fallback since its `Blob` is complete).
 *
 * @returns {(new () => FileReaderLike) | undefined}
 */
function fileReaderConstructor(): (new () => FileReaderLike) | undefined {
  const ctor = (globalThis as { FileReader?: unknown }).FileReader
  return typeof ctor === 'function'
    ? (ctor as new () => FileReaderLike)
    : undefined
}

/**
 * Runs one `FileReader` read to completion as a Promise. The reader is created
 * and its handlers attached before the read is started, so a synchronously
 * completing implementation cannot fire before anything is listening.
 *
 * @param options {object}
 * @param options.blob {Blob}                           the blob to read
 * @param options.read {Function}                       starts the read on the
 *   reader (`readAsText` or `readAsArrayBuffer`)
 * @param options.what {string}                         named in the error when
 *   the read fails or yields an unusable `result`
 * @returns {Promise<unknown>}   the reader's `result`
 */
async function readWithFileReader({
  blob,
  read,
  what
}: {
  blob: Blob
  read: (reader: FileReaderLike, blob: Blob) => void
  what: string
}): Promise<unknown> {
  const FileReaderCtor = fileReaderConstructor()
  if (FileReaderCtor === undefined) {
    throw new TypeError(
      `Cannot read ${what} from a Blob: this Blob implements neither the ` +
        'native read methods nor is a global FileReader available.'
    )
  }
  return await new Promise<unknown>((resolve, reject) => {
    const reader = new FileReaderCtor()
    reader.onload = () => {
      resolve(reader.result)
    }
    reader.onerror = () => {
      reject(
        reader.error instanceof Error
          ? reader.error
          : new Error(`Failed to read ${what} from a Blob.`)
      )
    }
    read(reader, blob)
  })
}

/**
 * A blob's contents as text, decoded as UTF-8.
 *
 * @param blob {Blob}
 * @returns {Promise<string>}
 */
export async function blobText(blob: Blob): Promise<string> {
  if (typeof blob.text === 'function') {
    return await blob.text()
  }
  const result = await readWithFileReader({
    blob,
    read: (reader, target) => {
      reader.readAsText(target)
    },
    what: 'text'
  })
  if (typeof result !== 'string') {
    throw new TypeError('FileReader.readAsText did not yield a string.')
  }
  return result
}

/**
 * A blob's contents as bytes.
 *
 * @param blob {Blob}
 * @returns {Promise<Uint8Array>}
 */
export async function blobBytes(blob: Blob): Promise<Uint8Array> {
  if (typeof blob.arrayBuffer === 'function') {
    return new Uint8Array(await blob.arrayBuffer())
  }
  const result = await readWithFileReader({
    blob,
    read: (reader, target) => {
      reader.readAsArrayBuffer(target)
    },
    what: 'bytes'
  })
  // RN's reader yields an ArrayBuffer; tolerate a typed-array result too,
  // since some polyfills hand back a view rather than the buffer itself.
  if (result instanceof ArrayBuffer) {
    return new Uint8Array(result)
  }
  if (ArrayBuffer.isView(result)) {
    return new Uint8Array(
      result.buffer as ArrayBuffer,
      result.byteOffset,
      result.byteLength
    )
  }
  throw new TypeError(
    'FileReader.readAsArrayBuffer did not yield an ArrayBuffer.'
  )
}

/**
 * Presents a binary payload as a `ReadableStream<Uint8Array>`. Bytes already
 * in hand become a one-chunk stream over that same buffer (no copy), so a
 * caller whose consumer reads across many awaits snapshots the buffer itself
 * if it may be reused meanwhile. A `Blob` is immutable and streams itself
 * where it implements `stream()`; React Native's built-in `Blob` does not, so
 * there the stream reads the blob's bytes through {@link blobBytes} on first
 * pull. A consumer that re-chunks what it reads (the EDV encrypt stream) is
 * unaffected by the shape of the source stream.
 *
 * @param data {Blob | Uint8Array}
 * @returns {ReadableStream<Uint8Array>}
 */
export function bytesToStream(
  data: Blob | Uint8Array
): ReadableStream<Uint8Array> {
  if (data instanceof Uint8Array) {
    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(data)
        controller.close()
      }
    })
  }
  if (typeof data.stream === 'function') {
    return data.stream() as ReadableStream<Uint8Array>
  }
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      controller.enqueue(await blobBytes(data))
      controller.close()
    }
  })
}

/**
 * One `Blob` over the given byte chunks, in order, typed `type` where given.
 * The native constructor does the concatenation. Where it refuses bytes
 * (React Native), the chunks are concatenated here and fetched back as a
 * `Blob` from a `data:` URL and retyped `type`. That fallback copies the
 * payload several times over, so a large resource is better read through the
 * streamed decode there.
 *
 * @param options {object}
 * @param options.parts {Uint8Array[]}   the chunks, in order
 * @param [options.type] {string}   the blob's content type
 * @returns {Promise<Blob>}
 */
export async function bytesToBlob({
  parts,
  type
}: {
  parts: Uint8Array[]
  type?: string
}): Promise<Blob> {
  try {
    return new Blob(parts as BlobPart[], { type })
  } catch (err) {
    if (!(err instanceof TypeError) || typeof fetch !== 'function') {
      throw err
    }
    const total = parts.reduce((sum, part) => sum + part.byteLength, 0)
    const bytes = new Uint8Array(total)
    let offset = 0
    for (const part of parts) {
      bytes.set(part, offset)
      offset += part.byteLength
    }
    // The URL names a fixed media type: `type` may carry parameters or other
    // characters a data: URL header cannot hold, so it is set on the result.
    const response = await fetch(
      `data:application/octet-stream;base64,${base64.encode(bytes)}`
    )
    const blob = await response.blob()
    return type === undefined ? blob : new Blob([blob], { type })
  }
}

/**
 * Drains a byte stream into one `Blob` of the given type, through
 * {@link bytesToBlob}. The stream is read with its own reader, so a stream
 * that errors rejects with that very error. Draining it through
 * `new Response(stream).arrayBuffer()` instead would lose the error in
 * Chromium, which rejects that read with a bare `TypeError: Failed to fetch`.
 * A chunk that is not bytes rejects with a `TypeError`, as `Response` would,
 * after cancelling the stream so its source is released.
 *
 * @param options {object}
 * @param options.stream {ReadableStream<Uint8Array>}
 * @param [options.type] {string}   the blob's content type
 * @returns {Promise<Blob>}
 */
export async function streamToBlob({
  stream,
  type
}: {
  stream: ReadableStream<Uint8Array>
  type?: string
}): Promise<Blob> {
  const parts: Uint8Array[] = []
  const reader = stream.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) {
      break
    }
    if (!(value instanceof Uint8Array)) {
      const err = new TypeError(
        'Cannot buffer this stream into a Blob: it yielded a chunk that is ' +
          'not a Uint8Array.'
      )
      await reader.cancel(err)
      throw err
    }
    parts.push(value)
  }
  return await bytesToBlob({
    parts,
    ...(type !== undefined && { type })
  })
}
