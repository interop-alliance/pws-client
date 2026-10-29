import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import type { WasClient as WasClientClass } from '../../src/index.js'
import type { Outcome } from './fixtures/chunked.js'

/**
 * Browser smoke test: confirms the bundle loads in a real browser and that the
 * lazy navigational handles build synchronously (no network, no key material).
 */
test('WasClient builds lazy handles in the browser', async ({ page }) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    // `/src/index.ts` is a Vite dev-server path resolved at runtime in the
    // browser; `tsc` cannot resolve the specifier, so the static type comes
    // from the type-only import above.
    // @ts-expect-error -- Vite-only module specifier, resolved at runtime.
    const { WasClient } = (await import('/src/index.ts')) as {
      WasClient: typeof WasClientClass
    }
    // The constructor only stores baseServerUrl + zcapClient; a minimal stub is
    // enough to exercise synchronous, network-free handle construction.
    const stubZcapClient = {
      invocationSigner: { id: 'did:example:1#key-1' }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const was = new WasClient({
      baseServerUrl: 'https://was.example/',
      zcapClient: stubZcapClient
    })
    const resource = was
      .spaceAt('https://was.example/space/s/')
      .collection('c')
      .resource('r')
    return {
      spaceUrl: resource.spaceUrl,
      collectionId: resource.collectionId,
      resourceId: resource.id,
      controllerDid: was.controllerDid
    }
  })
  expect(result).toEqual({
    spaceUrl: 'https://was.example/space/s/',
    collectionId: 'c',
    resourceId: 'r',
    controllerDid: 'did:example:1'
  })
})

/**
 * A chunked decrypt buffered to a `Blob` keeps the stream's own error in a
 * real browser. Node propagates the error through a `Response`-based drain
 * too, so only a browser can catch a regression to that drain (see
 * `streamToBlob`).
 */
test.describe('chunked decrypt in the browser', () => {
  async function decryptWith(
    page: Page,
    failure: 'none' | 'missing' | 'tampered'
  ): Promise<Outcome> {
    await page.goto('/test/index.html')
    return await page.evaluate(async mode => {
      // A Vite dev-server path resolved at runtime in the browser; the static
      // type comes from the type-only import of the fixture module.
      const specifier = '/test/browser/fixtures/chunked.ts'
      const { decryptChunked } = (await import(
        /* @vite-ignore */ specifier
      )) as typeof import('./fixtures/chunked.js')
      return await decryptChunked(mode)
    }, failure)
  }

  test('round-trips the bytes', async ({ page }) => {
    expect(await decryptWith(page, 'none')).toEqual({ ok: true, bytes: 64 })
  })

  test('surfaces NotFoundError for a missing chunk', async ({ page }) => {
    const outcome = await decryptWith(page, 'missing')
    expect(outcome).toMatchObject({ name: 'NotFoundError' })
    expect('message' in outcome && outcome.message).toMatch(/chunk 1/)
  })

  test('surfaces EncryptionError for a tampered chunk', async ({ page }) => {
    const outcome = await decryptWith(page, 'tampered')
    expect(outcome).toMatchObject({ name: 'EncryptionError' })
    expect('message' in outcome && outcome.message).toMatch(/failed to decrypt/)
  })
})
