/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The top-level WAS client. Wraps an ezcap `ZcapClient` (which holds the active
 * signer) and exposes the WAS containment model
 * (`SpacesRepository > Space > Collection > Resource`) through lazy
 * navigational handles. Also hosts the general delegation primitive
 * (`grant`), capability-rebuilding (`fromCapability`), the signed
 * escape-hatch (`request`), and service discovery (`service`), which every
 * signed request waits on.
 *
 * A server that addresses Spaces by id is identified by its base server URL,
 * under which the spec's Server Layout fixes `{base}service`, `{base}spaces/`
 * and `{base}space/{space_id}/`. The client is built from that base
 * (`new WasClient({ baseServerUrl })`) and constructs the three itself;
 * `space(id)` opens a Space by id. A Space URL the client is handed (the
 * `Location` of the create response, a capability's target, a DID, a stored
 * pointer) is authoritative as given: `spaceAt(url)` opens it, and nothing
 * rewrites it to fit the base. A server that is one fixed Space, with no id
 * and no base server URL, is opened from the Space URL alone
 * (`WasClient.forSpace({ spaceUrl })`); that client finds the service
 * description through the `service` link and refuses the id-addressed
 * operations.
 */
import type { ZcapClient } from '@interop/ezcap'
import { isValidTarget } from '@interop/zcap'
import type { HttpResponse } from '@interop/http-client'
import type { ServiceDescription } from '@interop/storage-core'
import { canonicalContainerUrl, parseSpaceTarget } from './internal/paths.js'
import {
  canonicalBaseServerUrl,
  canonicalSpaceUrl,
  parseAbsoluteHttpUrl,
  serviceDescriptionUrl,
  spacesRepositoryUrl,
  spaceUrlById,
  splitCollectionUrl
} from './internal/layout.js'
import type { ClientContext } from './internal/request.js'
import { send, rawRequest, unsignedRequest } from './internal/request.js'
import { parseResource, readJsonData } from './internal/content.js'
import {
  buildPageWalk,
  collectPages,
  collectWalk,
  signedPageWalk,
  walkItems,
  walkPagesOrEmpty
} from './internal/pagination.js'
import type { PageWalk } from './internal/pagination.js'
import { delegateGrant } from './internal/grant.js'
import { submitRevocation } from './internal/revoke.js'
import { spaceUrlOf } from './internal/rootCapability.js'
import { Memo } from './internal/memo.js'
import {
  discoverService,
  readServiceDescription,
  selectServiceVersion
} from './internal/service.js'
import {
  IncompatibleServerError,
  NotSupportedError,
  ValidationError,
  WasServerError
} from './errors.js'
import { zcapClientForSigner } from './zcapClient.js'
import type { EncryptionProvider } from './codec.js'
import { Space } from './Space.js'
import { Collection } from './Collection.js'
import { Resource } from './Resource.js'
import type {
  EncryptionOverride,
  GrantOptions,
  HandleOptions,
  IDelegatedZcap,
  ISigner,
  IZcap,
  Json,
  RequestInput,
  CollectionResourcesList,
  ResourceSummary,
  ServiceInfo,
  SpaceListing
} from './types.js'

/**
 * The module-private key under which {@link WasClient.forSpace} hands the
 * constructor a Space URL in place of a base server URL. A `unique symbol`
 * keeps that arm off the public constructor: a caller holding a Space URL goes
 * through `forSpace`, which documents what such a client can and cannot do.
 */
const fixedSpace: unique symbol = Symbol('WasClient.forSpace')

export class WasClient {
  /**
   * The base server URL the client was built from, in canonical form
   * (trailing slash supplied): the URL under which the server lays out
   * `service`, `spaces/` and `space/{space_id}/`. `undefined` for a client
   * built by {@link WasClient.forSpace}, which has none.
   */
  readonly baseServerUrl?: string
  /**
   * The Space URL a client built by {@link WasClient.forSpace} was opened on,
   * in canonical form. `undefined` for a client built from a base server URL.
   */
  readonly spaceUrl?: string
  readonly zcapClient: ZcapClient
  readonly encryption?: EncryptionProvider

  /**
   * @param options {object}
   * @param options.baseServerUrl {string}   the server's base server URL: an
   *   absolute http(s) URL with no query, fragment, or userinfo, under which
   *   the server serves `service`, `spaces/` and `space/{space_id}/`. A
   *   missing trailing slash is supplied. For a server that is one fixed
   *   Space with no base, use {@link WasClient.forSpace} instead
   * @param options.zcapClient {ZcapClient}   an ezcap client holding the signer
   * @param [options.encryption] {EncryptionProvider}   the keystore that
   *   supplies keys for collections declared encrypted (by their `encryption`
   *   descriptor or a per-handle override); built by the
   *   `@interop/was-client/edv` subpath. Omit for plaintext-only clients. It
   *   does not decide *which* collections are encrypted -- that is the
   *   descriptor/override -- so a missing key for an encrypted collection fails
   *   closed rather than silently downgrading to plaintext.
   * @param [options.serviceDescription] {ServiceDescription}   a service
   *   description the caller already holds (from a cache, say). The client
   *   selects its version from this copy instead of discovering the document,
   *   and still refuses it with `IncompatibleServerError` if it names no
   *   version this client speaks, or (for a client built from a base server
   *   URL) if it describes another server (see {@link service}).
   *   `service({ refresh: true })` discards it and discovers afresh.
   * @throws {ValidationError}   when `baseServerUrl` is not an absolute
   *   http(s) URL, or carries a query, fragment, or userinfo
   */
  constructor(
    options: {
      zcapClient: ZcapClient
      encryption?: EncryptionProvider
      serviceDescription?: ServiceDescription
    } & ({ baseServerUrl: string } | { [fixedSpace]: string })
  ) {
    if (fixedSpace in options) {
      this.spaceUrl = canonicalSpaceUrl(options[fixedSpace])
    } else {
      this.baseServerUrl = canonicalBaseServerUrl(options.baseServerUrl)
    }
    this.zcapClient = options.zcapClient
    this.encryption = options.encryption
    this.#serviceDescription = options.serviceDescription
  }

  /**
   * Opens a client on a single fixed Space: a server that is one Space with
   * no Space id and no base server URL (a personal site whose Collections are
   * `https://alice.example/posts/`, `https://alice.example/images/`, ...).
   * The service description is found by following the `service` link on an
   * unsigned `HEAD` of the Space URL. The Space itself is
   * `was.spaceAt(was.spaceUrl)`, and `collectionAt(url)` opens one of its
   * Collections directly.
   *
   * Such a client has no base server URL, so `space(id)`, `createSpace()` and
   * `listSpaces()` throw `NotSupportedError`. Everything Space-scoped
   * (`spaceAt`, `collectionAt`, `fromCapability`, `grant`, `revoke`, the
   * public reads) works as on any client. Whether the server lets a client
   * create Collections is read from its `collection-management` feature
   * token, as for every server.
   *
   * @param options {object}
   * @param options.spaceUrl {string}   the Space's absolute URL, which may be
   *   an origin root
   * @param [options.zcapClient] {ZcapClient}   an ezcap client holding the
   *   signer; one of `zcapClient` and `signer` is given
   * @param [options.signer] {ISigner}   a signer to build the `ZcapClient`
   *   from, as {@link fromSigner} does
   * @param [options.encryption] {EncryptionProvider}   see the constructor
   * @param [options.serviceDescription] {ServiceDescription}   see the
   *   constructor; not checked against the Space URL, which names no server
   * @returns {WasClient}
   * @throws {ValidationError}   when `spaceUrl` is not a Space URL, or neither
   *   or both of `zcapClient` and `signer` are given
   */
  static forSpace({
    spaceUrl,
    zcapClient,
    signer,
    encryption,
    serviceDescription
  }: {
    spaceUrl: string
    zcapClient?: ZcapClient
    signer?: ISigner
    encryption?: EncryptionProvider
    serviceDescription?: ServiceDescription
  }): WasClient {
    if ((zcapClient === undefined) === (signer === undefined)) {
      throw new ValidationError(
        'WasClient.forSpace takes exactly one of `zcapClient` and `signer`.'
      )
    }
    return new WasClient({
      [fixedSpace]: spaceUrl,
      zcapClient:
        zcapClient ?? zcapClientForSigner({ signer: signer as ISigner }),
      encryption,
      serviceDescription
    })
  }

  /**
   * Convenience constructor that builds the ezcap `ZcapClient` internally from
   * a signer, using the `eddsa-jcs-2022` suite for delegation proofs.
   *
   * The suite is fixed rather than an option: a caller who needs a different
   * one builds the `ZcapClient` itself and passes it to the constructor.
   * `eddsa-jcs-2022` canonicalizes with JCS, so delegating never runs URDNA2015
   * and never needs a JSON-LD document loader to serve the suite's context.
   *
   * @param options {object}
   * @param options.baseServerUrl {string}   see the constructor
   * @param options.signer {ISigner}
   * @param [options.encryption] {EncryptionProvider}   see the constructor
   * @param [options.serviceDescription] {ServiceDescription}   see the
   *   constructor
   * @returns {WasClient}
   */
  static fromSigner({
    baseServerUrl,
    signer,
    encryption,
    serviceDescription
  }: {
    baseServerUrl: string
    signer: ISigner
    encryption?: EncryptionProvider
    serviceDescription?: ServiceDescription
  }): WasClient {
    return new WasClient({
      baseServerUrl,
      zcapClient: zcapClientForSigner({ signer }),
      encryption,
      serviceDescription
    })
  }

  /**
   * The DID controlling the wrapped signer (`signer.id` without the key
   * fragment). Used to default `controller` on `createSpace`.
   *
   * @returns {string}
   */
  get controllerDid(): string {
    const signer = this.zcapClient.invocationSigner
    if (!signer?.id) {
      throw new ValidationError(
        'The wrapped ZcapClient has no invocationSigner id.'
      )
    }
    return signer.id.split('#')[0] as string
  }

  #serviceDescription?: ServiceDescription

  readonly #service = new Memo<ServiceInfo>(async () => {
    let info: ServiceInfo
    if (this.#serviceDescription !== undefined) {
      info = selectServiceVersion(this.#serviceDescription)
    } else if (this.baseServerUrl !== undefined) {
      info = await readServiceDescription({
        serviceUrl: serviceDescriptionUrl({
          baseServerUrl: this.baseServerUrl
        })
      })
    } else {
      info = await discoverService({ url: this.spaceUrl as string })
    }
    this.#assertDescribesThisServer(info)
    return info
  })

  /**
   * Refuses a service description that does not describe the server at this
   * client's base server URL: its `url` must be `{base}service` and its
   * `spaces` member, when present, `{base}spaces/`. A caller-supplied copy
   * keyed wrongly or kept across deployments, or a base that names a
   * different mount than the server's, would otherwise fail later with a 404
   * deep in a Space; refusing here names both values. A client built by
   * {@link forSpace} has no base and is not checked.
   *
   * @param info {ServiceInfo}
   * @throws {IncompatibleServerError}
   */
  #assertDescribesThisServer(info: ServiceInfo): void {
    if (this.baseServerUrl === undefined) {
      return
    }
    const expectedUrl = serviceDescriptionUrl({
      baseServerUrl: this.baseServerUrl
    })
    const describedUrl = parseAbsoluteHttpUrl(info.description.url)?.toString()
    if (describedUrl !== expectedUrl) {
      throw new IncompatibleServerError(
        `The service description names itself "${info.description.url}", ` +
          `but the base server URL "${this.baseServerUrl}" places it at ` +
          `"${expectedUrl}".`
      )
    }
    if (info.spacesUrl === undefined) {
      return
    }
    const expectedSpaces = spacesRepositoryUrl({
      baseServerUrl: this.baseServerUrl
    })
    // `selectServiceVersion` stores `spacesUrl` in canonical container form.
    if (info.spacesUrl !== expectedSpaces) {
      throw new IncompatibleServerError(
        `The service description names the Spaces Repository ` +
          `"${info.spacesUrl}", but the base server URL ` +
          `"${this.baseServerUrl}" places it at "${expectedSpaces}".`
      )
    }
  }

  /**
   * Reads the server's service description and selects the WAS version this
   * client speaks with it. A client built from a base server URL reads
   * `{base}service` with an unsigned `GET` and checks that the document
   * describes that base (its `url` and `spaces` members agree with the
   * layout); one built by {@link forSpace} follows the `rel="service"` link on
   * the response to an unsigned `HEAD` of the Space URL. No capability is
   * invoked. The result is memoized for the life of the client and shared by
   * every handle; concurrent callers share one discovery, and a failure is
   * not memoized, so the next call retries.
   *
   * Every signed request waits on this discovery, so a caller rarely needs to
   * call it first. It is the way to read the server-wide affordances:
   * `features` (an open token list -- e.g. `changes-query` -- where an absent
   * token means unsupported) and `spacesUrl` (absent when the server has no
   * Spaces Repository).
   * Unsigned public reads (`publicRead`, `publicListCollection`, ...) address
   * an absolute URL that may be on another server, and do not wait on it.
   *
   * @param [options] {object}
   * @param [options.refresh] {boolean}   discard the memoized result (and any
   *   constructor-supplied `serviceDescription`) and discover again, for a
   *   caller about to rely on an affordance the server may have stopped
   *   advertising
   * @returns {Promise<ServiceInfo>}
   * @throws {IncompatibleServerError}   when the probed response carries no
   *   `service` link (the server predates v0.5), the document is malformed,
   *   it lists no version this client speaks, or it does not describe the
   *   server at this client's base server URL
   */
  async service(options: { refresh?: boolean } = {}): Promise<ServiceInfo> {
    if (options.refresh) {
      this.#serviceDescription = undefined
      this.#service.reset()
    }
    return this.#service.get()
  }

  /**
   * The base server URL, or the `NotSupportedError` a client built by
   * {@link forSpace} throws from every id-addressed operation.
   *
   * @param operation {string}   the operation's name, for the error
   * @returns {string}
   * @throws {NotSupportedError}
   */
  #requireBase(operation: string): string {
    if (this.baseServerUrl === undefined) {
      throw new NotSupportedError(
        `${operation} needs a base server URL, and this client was opened ` +
          `on the single fixed Space "${this.spaceUrl}", which has none.`
      )
    }
    return this.baseServerUrl
  }

  /**
   * The Spaces Repository URL the service description names, which the
   * layout check in discovery has already confirmed is `{base}spaces/`
   * (every signed request waits on discovery anyway).
   *
   * @param operation {string}   the operation's name, for the error
   * @returns {Promise<string>}
   * @throws {NotSupportedError}   when the client has no base server URL, or
   *   the server does not implement the Spaces Repository
   */
  async #spacesRepositoryUrl(operation: string): Promise<string> {
    this.#requireBase(operation)
    const { spacesUrl, version, description } = await this.service()
    if (spacesUrl === undefined) {
      throw new NotSupportedError(
        `The server at "${description.url}" does not implement the Spaces ` +
          `Repository: its WAS ${version} service description entry has no ` +
          '`spaces` URL.'
      )
    }
    return spacesUrl
  }

  #cachedContext?: ClientContext

  get #context(): ClientContext {
    // `zcapClient` and `encryption` are constructor-fixed, so the context is
    // derived once and reused rather than reallocating the object on every
    // handle access.
    if (this.#cachedContext === undefined) {
      const readControllerDid = () => this.controllerDid
      this.#cachedContext = {
        zcapClient: this.zcapClient,
        // Read lazily, so building a handle costs nothing and a
        // delegation-only client (a `ZcapClient` with a delegation signer and
        // no invocation signer) can still `grant()` and navigate. Only
        // `createSpace`'s controller default and `rootCapability`'s
        // client-side controller consult it, and both of those do invoke.
        get controllerDid(): string {
          return readControllerDid()
        },
        encryption: this.encryption,
        service: () => this.service()
      }
    }
    return this.#cachedContext
  }

  /**
   * Returns a lazy handle to a Space by its absolute URL, as the server
   * named it (the `Location` of the create response, a listing item's `url`,
   * a stored pointer, or the URL a self-locating DID resolves to). No I/O.
   * The URL is canonicalized (see `canonicalSpaceUrl` on the `./paths`
   * entry), and every Collection and Resource URL derives from it.
   *
   * @param spaceUrl {string}
   * @param options {object}
   * @param [options.capability] {IZcap}
   * @param [options.encryption] {EncryptionOverride}   the default encryption
   *   override for the Collections reached through this Space handle (see
   *   `EncryptionOverride`); `space.collection(id, { encryption })` overrides
   *   it per collection
   * @returns {Space}
   * @throws {ValidationError}   when `spaceUrl` is not a Space URL
   */
  spaceAt(spaceUrl: string, options: HandleOptions = {}): Space {
    return new Space({
      context: this.#context,
      spaceUrl,
      capability: options.capability,
      encryption: options.encryption
    })
  }

  /**
   * Returns a lazy handle to the Space with id `spaceId` on this client's
   * server, at `{base}space/{spaceId}/` as the spec's Server Layout places
   * it. No I/O. The same handle as `spaceAt` opened on that URL; the Space
   * need not exist yet (`space.configure(...)` with `ifNoneMatch` creates it
   * by id).
   *
   * @param spaceId {string}
   * @param options {object}
   * @param [options.capability] {IZcap}
   * @param [options.encryption] {EncryptionOverride}   see {@link spaceAt}
   * @returns {Space}
   * @throws {NotSupportedError}   on a client built by {@link forSpace}, which
   *   has no base server URL
   * @throws {ValidationError}   when `spaceId` is empty or a dot segment
   */
  space(spaceId: string, options: HandleOptions = {}): Space {
    const baseServerUrl = this.#requireBase('space(id)')
    return this.spaceAt(spaceUrlById({ baseServerUrl, spaceId }), options)
  }

  /**
   * Returns a lazy handle to a Collection by its absolute URL: the parent
   * container is its Space and the last segment its id, so the handle is
   * what `spaceAt(parent).collection(id)` would produce. No I/O. The direct
   * route for a single fixed Space, where a caller typically holds the
   * Collection URLs (`https://alice.example/posts/`) and nothing else.
   *
   * @param collectionUrl {string}
   * @param options {object}
   * @param [options.capability] {IZcap}
   * @param [options.encryption] {EncryptionOverride}
   * @returns {Collection}
   * @throws {ValidationError}   when `collectionUrl` is not a Collection URL
   *   (no path segment beneath its origin, a query or fragment), its last
   *   segment is a reserved Collection id, or it is not in canonical form
   *   (so the handle's requests would address a different URL)
   */
  collectionAt(collectionUrl: string, options: HandleOptions = {}): Collection {
    const { spaceUrl, collectionId } = splitCollectionUrl(collectionUrl)
    const handle = new Collection({
      context: this.#context,
      spaceUrl,
      collectionId,
      capability: options.capability,
      encryption: options.encryption
    })
    // The handle re-encodes the decoded id, so a URL whose last segment is
    // serialized differently (`%21` for `!`, lower-case hex) would build a
    // handle at another URL: one a bound capability does not cover, and
    // whose root capability id the server never minted. Refuse it, by name,
    // as `fromCapability` does for a non-canonical target.
    const expected = canonicalContainerUrl(collectionUrl)
    if (handle.url !== expected) {
      throw new ValidationError(
        `"${collectionUrl}" is not in canonical form: the handle would ` +
          `address "${handle.url}" instead.`
      )
    }
    return handle
  }

  /**
   * Creates a space (server-generated id unless `id` is given). `name` is
   * optional (both in the spec and on the reference server); `controller` must
   * match the wrapped signer's DID (which is the default). The request goes
   * to the Spaces Repository, `{base}spaces/`, and the returned handle is
   * opened on the Space URL the response's `Location` names, as the server
   * states it.
   *
   * @param desc {object}
   * @param [desc.id] {string}
   * @param [desc.name] {string}
   * @param [desc.controller] {string}
   * @param [desc.type] {string[]}   the Space Metadata object's `type` array,
   *   for a typed Space such as an auxiliary one (`['AuxiliarySpace',
   *   'Space']`). The server defaults it to `['Space']` and treats it as
   *   immutable after creation
   * @returns {Promise<Space>}
   * @throws {NotSupportedError}   when the server has no Spaces Repository, or
   *   the client was built by {@link forSpace}
   * @throws {WasServerError}   when the create response carries no `Location`
   */
  async createSpace(
    desc: {
      id?: string
      name?: string
      controller?: string
      type?: string[]
    } = {}
  ): Promise<Space> {
    const controller = desc.controller ?? this.controllerDid
    const body = {
      controller,
      ...(desc.id !== undefined && { id: desc.id }),
      ...(desc.name !== undefined && { name: desc.name }),
      ...(desc.type !== undefined && { type: desc.type })
    }
    const spacesUrl = await this.#spacesRepositoryUrl('createSpace')
    const response = await send(this.#context, {
      url: spacesUrl,
      method: 'POST',
      json: body
    })
    // Only the `Location` is needed here: the Space id is read off the Space
    // URL by the handle, so the response body's `id` goes unread.
    const location = response?.headers.get('location')
    if (!location) {
      throw new WasServerError(
        `The Create Space response from "${spacesUrl}" carries no ` +
          '`Location` header, so the new Space cannot be located.'
      )
    }
    // RFC 9110 permits a relative `Location`; resolve it against the request
    // URL so the handle is opened on an absolute Space URL.
    return this.spaceAt(new URL(location, spacesUrl).toString())
  }

  /**
   * Lists the spaces in the repository visible to the wrapped signer, as a
   * `{ url, totalItems, items }` listing. Visibility is per-controller: the
   * result holds every space whose controller the signed invocation is
   * authorized for, auxiliary spaces included. Each item carries the space's
   * `type` array, the same value as its Space Metadata object's `type`, so a
   * caller can tell an auxiliary space (one whose `type` names
   * `AuxiliarySpace`) from a user-data one without reading each space, and
   * its `url`, the Space URL to open a handle on with {@link spaceAt}.
   * An unauthorized caller is not an error -- the server
   * returns an empty `items` list (the spec's explicit exception to 404
   * masking), so nothing is revealed about which spaces exist.
   *
   * Transparently follows the server's `next` pagination links, buffering every
   * page into a single listing. The returned envelope omits `next`, and its
   * `totalItems` counts the collected items.
   *
   * @returns {Promise<SpaceListing>}
   * @throws {NotSupportedError}   when the server has no Spaces Repository, or
   *   the client was built by {@link forSpace}
   * @throws {WasServerError}   when the listing cannot be read in full
   */
  async listSpaces(): Promise<SpaceListing> {
    const spacesUrl = await this.#spacesRepositoryUrl('listSpaces')
    const walk = await signedPageWalk<SpaceListing>(this.#context, {
      firstUrl: spacesUrl
    })
    // The first page always carries the listing body (an unauthorized caller
    // still gets an empty `items` list, not an error), so a `null` walk is a
    // server fault -- a 404 at the advertised repository URL, or a 2xx whose
    // body did not parse as JSON. Report it as one, rather than as a
    // `TypeError` from destructuring `null`.
    if (walk === null) {
      throw new WasServerError(
        `The space listing at "${spacesUrl}" answered with no JSON body.`
      )
    }
    return collectPages(walk)
  }

  /**
   * Reads a public (`PublicCanRead`) resource by its URL with no authorization
   * -- an unsigned `GET`, for consuming a shared public link. Auto-parses JSON
   * to an object and returns binary as a `Blob`. Returns `null` if the resource
   * is missing or not publicly readable (404 conflation caveat).
   *
   * @param options {object}
   * @param options.resourceUrl {string}   the absolute resource URL
   * @returns {Promise<Json | Blob | null>}
   */
  async publicRead({
    resourceUrl
  }: {
    resourceUrl: string
  }): Promise<Json | Blob | null> {
    const response = await unsignedRequest({
      url: resourceUrl,
      method: 'GET',
      read: true
    })
    return parseResource(response)
  }

  /**
   * Reads the first page of a public (`PublicCanRead`) collection listing with
   * an unsigned `GET` and packages the means to follow its `next` links.
   * Returns `null` if the collection is missing or not publicly readable (404
   * conflation caveat).
   *
   * @param collectionUrl {string}   the absolute collection URL
   * @returns {Promise<PageWalk | null>}
   */
  async #publicListWalk(collectionUrl: string): Promise<PageWalk | null> {
    return buildPageWalk({
      // The collection listing endpoint is the trailing-slash items URL.
      firstUrl: canonicalContainerUrl(collectionUrl),
      fetchPage: async pageUrl => {
        const pageResponse = await unsignedRequest({
          url: pageUrl,
          method: 'GET',
          read: true
        })
        return pageResponse === null
          ? null
          : ((await readJsonData(pageResponse)) as CollectionResourcesList)
      }
    })
  }

  /**
   * Lists a public (`PublicCanRead`) collection by its URL with no authorization
   * -- an unsigned `GET` -- e.g. to browse a blog published as a public-read
   * collection. Transparently follows the server's `next` pagination links,
   * buffering every page into a single list (the returned envelope omits
   * `next`). For a large collection prefer `publicListCollectionPages()` or
   * `publicListCollectionItems()`, which stream one page at a time and allow
   * stopping early. Returns `null` if the collection is missing or not publicly
   * readable (404 conflation caveat).
   *
   * @param options {object}
   * @param options.collectionUrl {string}   the absolute collection URL
   * @returns {Promise<CollectionResourcesList | null>}
   */
  async publicListCollection({
    collectionUrl
  }: {
    collectionUrl: string
  }): Promise<CollectionResourcesList | null> {
    return collectWalk(await this.#publicListWalk(collectionUrl))
  }

  /**
   * Lazily yields a public collection listing one page at a time, following the
   * server's `next` links on demand with unsigned `GET`s. Use this to stream a
   * large public collection in constant memory or to stop early. Yields nothing
   * if the collection is missing or not publicly readable (404 conflation
   * caveat).
   *
   * @param options {object}
   * @param options.collectionUrl {string}   the absolute collection URL
   * @returns {AsyncGenerator<CollectionResourcesList>}
   */
  async *publicListCollectionPages({
    collectionUrl
  }: {
    collectionUrl: string
  }): AsyncGenerator<CollectionResourcesList> {
    yield* walkPagesOrEmpty(await this.#publicListWalk(collectionUrl))
  }

  /**
   * Lazily yields each item of a public collection across every page,
   * flattening `publicListCollectionPages()`. Yields the listing's
   * `ResourceSummary` entries (id / url / contentType / name), not the resource
   * bodies. Yields nothing if the collection is missing or not publicly
   * readable (404 conflation caveat).
   *
   * @param options {object}
   * @param options.collectionUrl {string}   the absolute collection URL
   * @returns {AsyncGenerator<ResourceSummary>}
   */
  async *publicListCollectionItems({
    collectionUrl
  }: {
    collectionUrl: string
  }): AsyncGenerator<ResourceSummary> {
    yield* walkItems(this.publicListCollectionPages({ collectionUrl }))
  }

  /**
   * Rebuilds an access handle from a received capability, returning a handle at
   * the depth implied by the capability's `invocationTarget` (space /
   * collection / resource), pre-bound with that capability. The Space is read
   * off the capability's delegation chain, which starts at the Space's root
   * capability (whose id encodes the Space URL), so a capability from any
   * server locates its own Space with no out-of-band base. The root's target
   * is taken to be the Space URL: a Space URL has no shape of its own, so a
   * chain rooted elsewhere (a bare `was.grant({ target })` for a server with
   * no Space hierarchy roots at its target) is read as if that target were
   * the Space, and the server refuses the handle's requests. See `spaceUrlOf`
   * on the `./paths` entry.
   *
   * A resource-scoped capability cannot read the Collection Metadata object, so
   * an encryption-capable client cannot discover whether the collection is
   * encrypted and fails closed on the first read or write. The `encryption`
   * option is the way through: an explicit override skips that discovery
   * (`'plaintext'`, or a descriptor plus keys the grantor handed over out of
   * band). On a Resource or Collection handle it is the per-handle override of
   * `collection.resource(id, options)`; on a Space handle it is the Space's
   * default, inherited by every `collection()` child unless that call states
   * its own.
   *
   * @param zcap {IZcap}
   * @param options {object}
   * @param [options.encryption] {EncryptionOverride}   per-handle encryption
   *   override for the returned handle (see `EncryptionOverride`)
   * @returns {Space | Collection | Resource}
   * @throws {ValidationError}   when the capability's chain starts at no root
   *   capability or at one whose target cannot be a Space URL, or its
   *   `invocationTarget` is not at or beneath that Space, addresses a
   *   reserved sub-resource with no navigational handle, or is not in
   *   canonical form (so the handle's requests would fall outside it)
   */
  fromCapability(
    zcap: IZcap,
    { encryption }: { encryption?: EncryptionOverride } = {}
  ): Space | Collection | Resource {
    const target = zcap.invocationTarget
    const spaceUrl = spaceUrlOf(zcap)
    // `parseSpaceTarget` owns the grammar beneath a Space: it percent-decodes
    // each segment (the builders re-encode every id) and classifies the full
    // segment list, so a sub-resource target (`{s}policy`, `{s}{c}/{r}/meta`,
    // ...) is refused rather than silently truncated to the nearest
    // containment handle, whose derived URLs would mismatch the capability's
    // invocation target.
    const parsed = parseSpaceTarget({ spaceUrl, target })
    if (parsed === null) {
      throw new ValidationError(
        `Cannot derive a handle from invocationTarget "${target}": it does ` +
          `not address anything at or beneath the Space "${spaceUrl}" the ` +
          'capability is rooted in.'
      )
    }
    if (parsed.kind === 'sub-resource') {
      throw new ValidationError(
        `invocationTarget "${target}" addresses a reserved ` +
          'sub-resource, which has no navigational handle. Invoke it via the ' +
          'owning handle instead (e.g. `space.getPolicy()` / ' +
          '`resource.meta()`), or use the `was.request()` escape hatch.'
      )
    }
    const context = this.#context
    let handle: Space | Collection | Resource
    if (parsed.kind === 'resource') {
      handle = new Resource({
        context,
        spaceUrl,
        collectionId: parsed.collectionId,
        resourceId: parsed.resourceId,
        capability: zcap,
        encryption
      })
    } else if (parsed.kind === 'collection') {
      handle = new Collection({
        context,
        spaceUrl,
        collectionId: parsed.collectionId,
        capability: zcap,
        encryption
      })
    } else {
      handle = new Space({ context, spaceUrl, capability: zcap, encryption })
    }
    // `send` matches every request URL against the capability's target by
    // string prefix, so a target in a non-canonical serialization (upper-case
    // host, explicit default port) would let the handle be built and then
    // refuse every request from it. Refuse it here, by name.
    if (
      !isValidTarget({
        invocationTarget: handle.url,
        baseInvocationTarget: target,
        allowTargetAttenuation: true
      })
    ) {
      throw new ValidationError(
        `invocationTarget "${target}" is not in canonical form: the handle ` +
          `would address "${handle.url}", which the capability does not cover.`
      )
    }
    return handle
  }

  /**
   * The general delegation primitive. Delegates a capability per `GrantOptions`
   * and returns the signed zcap to hand off out-of-band. `target` (any URL),
   * `spaceUrl` (the Space to root a revocable grant in) and `capability` (a
   * parent capability to attenuate) make this a superset of the
   * `space`/`collection` grant sugar, which fills the first two from the
   * handle. Without `spaceUrl` or `capability`, the grant is rooted at the
   * target's own root capability: the shape for a server with no Space
   * hierarchy (fixed collections, or resources alone), where there is no
   * Space to root a chain in. Such a grant is not Space-revocable.
   *
   * @param options {GrantOptions}
   * @returns {Promise<IDelegatedZcap>}
   */
  async grant(options: GrantOptions): Promise<IDelegatedZcap> {
    return delegateGrant(this.#context, options)
  }

  /**
   * The general revocation primitive -- the inverse of {@link grant}. Reads
   * the owning Space off the capability's delegation chain (a Space-rooted
   * chain starts at the Space's root capability) and submits it to that
   * Space's revocation endpoint. Equivalent to `was.spaceAt(url).revoke(zcap)`.
   * The chain root's target is taken to be the Space (see `spaceUrlOf` on the
   * `./paths` entry); the server refuses a chain not rooted exactly in it.
   *
   * Revocation is scoped to one space: there is no cross-space or global
   * revocation. See {@link Space.revoke} for who may call it, what it does and
   * does not withdraw, and why it is not idempotent.
   *
   * @param zcap {IDelegatedZcap}   the delegated capability to revoke
   * @returns {Promise<void>}
   * @throws {ValidationError}   when the capability's chain starts at no root
   *   capability, or at one whose target cannot be a Space URL
   */
  async revoke(zcap: IDelegatedZcap): Promise<void> {
    return submitRevocation(this.#context, {
      spaceUrl: spaceUrlOf(zcap),
      zcap
    })
  }

  /**
   * The signed escape hatch, mirroring ezcap's generic `request()`. Takes an
   * absolute `url`, defaults `action` to `method`, uppercases both (as
   * {@link grant} does, so `'put'` signs `PUT`), and signs via the wrapped
   * client. Returns the raw `HttpResponse` and throws raw ky/ezcap
   * errors -- it does not apply the null-on-404 or typed-error conveniences.
   * Like every signed request it waits on {@link service} first, and rejects
   * with its `IncompatibleServerError` before signing anything.
   *
   * @param options {RequestInput}
   * @returns {Promise<HttpResponse>}
   */
  async request(options: RequestInput): Promise<HttpResponse> {
    return rawRequest(this.#context, options)
  }
}
