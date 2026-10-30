/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Pagination helpers for PWS list responses. A paginated listing carries a
 * `next` continuation URL when more items may follow; its absence is the
 * authoritative end-of-list signal (the spec forbids inferring page count from
 * `totalItems`). `walkPages` is the single traversal core: it follows `next`
 * from page to page, dereferencing each with the same authorization as the first
 * request, and yields one page at a time (constant memory, early-exit-friendly).
 * `collectPages` builds on it to eagerly aggregate every page into one envelope.
 *
 * The server's `next` is untrusted input. Following it attaches a signed
 * invocation (and, with no bound capability, a root zcap synthesized for
 * whatever URL is requested), so `walkPages` only follows a `next` that stays
 * within the first page's origin and base path, and stops after a bounded
 * number of pages. Either violation fails the walk with a `PwsServerError`.
 *
 * The helpers are generic over the listing envelope, so they serve all three
 * paginated PWS listings: List Collection items (`CollectionResourcesList`),
 * List Collections (`CollectionsList`), and List Spaces (`SpaceListing`). Each
 * envelope shares the `{ items, next?, totalItems? }` shape (`PageEnvelope`)
 * that the traversal and the aggregation rely on.
 */
import type {
  CollectionResourcesList,
  IZcap,
  ResourceSummary
} from '../types.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { dataOrNull } from './content.js'
import { PwsServerError } from '../errors.js'
import { hasUserinfo } from './layout.js'

/**
 * The default page-count bound on one listing walk. Generous enough for any
 * real listing, but it stops a server whose every page returns a fresh cursor
 * from driving an unbounded number of requests.
 */
export const DEFAULT_MAX_PAGES = 10_000

/**
 * The shared shape of every paginated listing envelope: an `items` array, an
 * optional `next` continuation URL, and the whole listing's `totalItems` count
 * (required on some listing types upstream, optional on others). The traversal
 * core only touches `items` and `next`; `collectPages` also sets `totalItems`.
 */
type PageEnvelope = { items: unknown[]; next?: string; totalItems?: number }

/**
 * The first page (already read) plus the means to fetch each following page.
 * The `fetchPage` callback fetches a single page by absolute URL, returning
 * `null` if it is missing/unauthorized. A `null` first page makes the walk
 * itself `null`; a `null` page mid-walk fails the walk, since a `next` the
 * server handed out has to resolve.
 */
export interface PageWalk<T extends PageEnvelope = CollectionResourcesList> {
  first: T
  firstUrl: string
  fetchPage: (url: string) => Promise<T | null>
}

/**
 * Builds a {@link PageWalk} by fetching the first page with the same
 * `fetchPage` used for every following page -- the shared shape of the signed
 * (`Collection.#listWalk`) and unsigned (`PwsClient.#publicListWalk`) walks,
 * which differ only in how a single page URL is fetched. Returns `null` when
 * the first page is missing/unauthorized (404 conflation caveat).
 *
 * @param options {object}
 * @param options.firstUrl {string}      the absolute listing URL
 * @param options.fetchPage {function}   fetches one page by absolute URL
 * @returns {Promise<PageWalk<T> | null>}
 */
export async function buildPageWalk<
  T extends PageEnvelope = CollectionResourcesList
>({
  firstUrl,
  fetchPage
}: {
  firstUrl: string
  fetchPage: PageWalk<T>['fetchPage']
}): Promise<PageWalk<T> | null> {
  const first = await fetchPage(firstUrl)
  return first === null ? null : { first, firstUrl, fetchPage }
}

/**
 * Builds a {@link PageWalk} whose every page is fetched with the same signed,
 * null-on-404 `GET` -- the one traversal shape shared by all three authorized
 * PWS listings (Collection items, Collections, Spaces), which differ only in
 * the first URL, the envelope type, and whether a capability is bound. Returns
 * `null` when the first page is missing/unauthorized (404 conflation caveat).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.firstUrl {string}      the absolute listing URL
 * @param [options.capability] {IZcap}   capability attached to every page
 *   request
 * @returns {Promise<PageWalk<T> | null>}
 */
export async function signedPageWalk<
  T extends PageEnvelope = CollectionResourcesList
>(
  context: ClientContext,
  { firstUrl, capability }: { firstUrl: string; capability?: IZcap }
): Promise<PageWalk<T> | null> {
  return buildPageWalk<T>({
    firstUrl,
    fetchPage: async url =>
      dataOrNull<T>(
        await send(context, { url, method: 'GET', capability, read: true })
      )
  })
}

/**
 * Resolves a server-supplied `next` against the URL of the page that produced
 * it, and checks that the result stays within the listing: the same origin as
 * the first page, a path equal to or under the first page's path, and no
 * username or password. A `next` that fails any check is never fetched, because
 * the fetch would carry the caller's signed invocation to wherever the server
 * pointed it.
 *
 * @param options {object}
 * @param options.next {unknown}     the `next` value from the page
 * @param options.baseUrl {string}   the URL of the page that produced it
 * @param options.firstUrl {URL}     the canonicalized first page URL
 * @returns {string} the absolute, canonicalized page URL
 * @throws {PwsServerError}   when `next` is not a URL or leaves the listing
 */
function resolveNext({
  next,
  baseUrl,
  firstUrl
}: {
  next: unknown
  baseUrl: string
  firstUrl: URL
}): string {
  const listingUrl = firstUrl.toString()
  let pageUrl: URL
  try {
    // A parsed body is untrusted: a non-string `next` would otherwise be
    // coerced into a relative path and followed.
    if (typeof next !== 'string') {
      throw new TypeError(`\`next\` is a ${typeof next}, not a string.`)
    }
    pageUrl = new URL(next, baseUrl)
  } catch (err) {
    throw new PwsServerError(
      `The listing at "${listingUrl}" served a \`next\` link that is not a ` +
        `URL: ${JSON.stringify(next)}.`,
      { requestUrl: listingUrl, cause: err }
    )
  }
  const basePath = firstUrl.pathname.endsWith('/')
    ? firstUrl.pathname
    : `${firstUrl.pathname}/`
  const sameOrigin =
    pageUrl.origin !== 'null' && pageUrl.origin === firstUrl.origin
  const underBasePath =
    pageUrl.pathname === firstUrl.pathname ||
    pageUrl.pathname.startsWith(basePath)
  if (!sameOrigin || !underBasePath || hasUserinfo(pageUrl)) {
    throw new PwsServerError(
      `The listing at "${listingUrl}" served a \`next\` link ` +
        `("${pageUrl.toString()}") outside its origin or base path, or ` +
        'with credentials in it. It was not followed.',
      { requestUrl: listingUrl }
    )
  }
  return pageUrl.toString()
}

/**
 * Lazily walks a list response page by page, yielding the first page and then
 * each page reached by following `next`. Each `next` is resolved relative to the
 * URL of the page that produced it. Yields one page at a time, so a consumer
 * can stop early without fetching the rest.
 *
 * The walk either reaches the server's end-of-list signal (a page with no
 * `next`) or fails. A `next` outside the first page's origin or base path, a
 * `next` carrying a username or password, a `next` pointing at an already-seen
 * page (a cycle), a page that walks past `maxPages`, or a followed page that
 * comes back `null` (missing/unauthorized) each fail with a `PwsServerError`
 * naming the listing URL. Ending silently on any of these would hand the
 * consumer a short listing it cannot tell from a complete one.
 *
 * @param walk {PageWalk<T>}
 * @param [options] {object}
 * @param [options.maxPages] {number}   the most pages to yield, counting the
 *   first (defaults to {@link DEFAULT_MAX_PAGES})
 * @returns {AsyncGenerator<T>}
 * @throws {PwsServerError}   when `next` leaves the listing, repeats a page, or
 *   fails to resolve, or when the page bound is hit
 */
export async function* walkPages<
  T extends PageEnvelope = CollectionResourcesList
>(
  walk: PageWalk<T>,
  { maxPages = DEFAULT_MAX_PAGES }: { maxPages?: number } = {}
): AsyncGenerator<T> {
  const { first, fetchPage } = walk
  // Canonicalize the first URL once: it is both the scope every `next` is
  // checked against and the seed of the cycle guard. Every followed `next` is
  // canonicalized via `new URL(...)`, so an equivalent-but-unequal seed (e.g.
  // an explicit default port) would let a next-link back to page 1 defeat the
  // guard and yield its items twice.
  const firstUrl = new URL(walk.firstUrl)
  const listingUrl = firstUrl.toString()
  yield first
  const seen = new Set<string>([listingUrl])
  let pageCount = 1
  let baseUrl = listingUrl
  let next = first.next
  while (next) {
    const pageUrl = resolveNext({ next, baseUrl, firstUrl })
    if (seen.has(pageUrl)) {
      throw new PwsServerError(
        `The listing at "${listingUrl}" served a \`next\` link ` +
          `("${pageUrl}") back to a page already walked.`,
        { requestUrl: listingUrl }
      )
    }
    if (pageCount >= maxPages) {
      throw new PwsServerError(
        `The listing at "${listingUrl}" did not end within ` +
          `${maxPages} pages.`,
        { requestUrl: listingUrl }
      )
    }
    seen.add(pageUrl)
    const page = await fetchPage(pageUrl)
    if (page === null) {
      throw new PwsServerError(
        `The listing at "${listingUrl}" served a \`next\` link ` +
          `("${pageUrl}") that answered with no listing (missing or ` +
          'unauthorized).',
        { requestUrl: pageUrl }
      )
    }
    pageCount += 1
    yield page
    baseUrl = pageUrl
    next = page.next
  }
}

/**
 * Eagerly follows every `next` link, aggregating all pages' items into a single
 * envelope shaped like the first page, with `next` dropped since the whole list
 * has been collected. Buffers the entire collection in memory; for a large
 * collection prefer `walkPages` (one page at a time) or an item iterator.
 *
 * `totalItems` on the aggregate is always the count of the collected items.
 * The server's value is not used, since a paginating server may omit it on a
 * truncated page and the first page's value may be stale by the time the last
 * page is read. The count is sound because `walkPages` either completes the
 * listing or throws.
 *
 * @param walk {PageWalk<T>}
 * @returns {Promise<T>}
 * @throws {PwsServerError}   when the walk cannot complete the listing
 */
export async function collectPages<
  T extends PageEnvelope = CollectionResourcesList
>(walk: PageWalk<T>): Promise<T> {
  let aggregate: T | undefined
  const items: T['items'] = []
  for await (const page of walkPages(walk)) {
    aggregate ??= page
    // Append one by one: spreading a page's items as call arguments would hit
    // the engine's max-arguments limit on a very large page.
    for (const item of page.items) {
      items.push(item)
    }
  }
  // `walkPages` always yields `first`, so `aggregate` is set here.
  const result: T = { ...aggregate!, items, totalItems: items.length }
  delete result.next
  return result
}

/**
 * The buffering list surface over a possibly-absent walk: collects every page
 * into one envelope, mapping a `null` walk (missing/unauthorized listing) to
 * `null`. The shared dispatch behind `Collection.list()` and
 * `PwsClient.publicListCollection()`.
 *
 * @param walk {PageWalk<T> | null}
 * @returns {Promise<T | null>}
 */
export async function collectWalk<
  T extends PageEnvelope = CollectionResourcesList
>(walk: PageWalk<T> | null): Promise<T | null> {
  return walk === null ? null : collectPages(walk)
}

/**
 * The lazy page surface over a possibly-absent walk: yields each page, or
 * nothing for a `null` walk (which an iterator cannot distinguish from an
 * empty listing). The shared dispatch behind `Collection.listPages()` and
 * `PwsClient.publicListCollectionPages()`.
 *
 * @param walk {PageWalk<T> | null}
 * @returns {AsyncGenerator<T>}
 */
export async function* walkPagesOrEmpty<
  T extends PageEnvelope = CollectionResourcesList
>(walk: PageWalk<T> | null): AsyncGenerator<T> {
  if (walk !== null) {
    yield* walkPages(walk)
  }
}

/**
 * The lazy item surface: flattens a page iterator into its `ResourceSummary`
 * entries. The shared dispatch behind `Collection.listItems()` and
 * `PwsClient.publicListCollectionItems()`.
 *
 * @param pages {AsyncIterable<CollectionResourcesList>}
 * @returns {AsyncGenerator<ResourceSummary>}
 */
export async function* walkItems(
  pages: AsyncIterable<CollectionResourcesList>
): AsyncGenerator<ResourceSummary> {
  for await (const page of pages) {
    yield* page.items
  }
}
