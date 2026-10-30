/**
 * Measures what a governed descriptor read costs in verification: a full
 * pass over a resource log of N entries whose states carry R wrapped
 * recipients each, against a resumed pass that holds the verification of
 * all but the last entry (one new entry since) and one that holds the whole
 * log (nothing new). Prints one row per (entries, recipients) with the
 * serialized log size and the mean wall time of each pass.
 *
 * Run `pnpm build` first.
 * Usage: node scripts/bench-log-verify.mjs [entries,...] [recipients,...]
 * Defaults: 10,100,300 entries and 1,10,50 recipients, 3 runs each.
 */
import { randomBytes } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { EPOCH_CONFIGURATION_STATE_TYPE } from '@interop/pws-client/edv'
import { RESOURCE_LOG_METHOD as METHOD } from '@interop/storage-core'
import {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  serializeResourceLog,
  verifyResourceLog
} from '@interop/vh-resource-log'
import { fakeController } from '@interop/vh-resource-log/testing'

const RUNS = 3
const [entryCounts, recipientCounts] = [
  process.argv[2] ?? '10,100,300',
  process.argv[3] ?? '1,10,50'
].map(list => list.split(',').map(Number))

function base64url(length) {
  return randomBytes(length).toString('base64url')
}

/**
 * A descriptor state shaped like an epoch configuration with `count`
 * wrapped recipients: one JWE recipient (ECDH-ES+A256KW header and wrapped
 * key) per reader.
 */
function descriptorState({ epoch, count }) {
  const recipients = Array.from({ length: count }, () => ({
    header: {
      kid: `did:key:z6Mk${base64url(32)}#z6Mk${base64url(32)}`,
      alg: 'ECDH-ES+A256KW',
      epk: { kty: 'OKP', crv: 'X25519', x: base64url(32) },
      apu: base64url(32),
      apv: base64url(32)
    },
    encrypted_key: base64url(40)
  }))
  return {
    type: EPOCH_CONFIGURATION_STATE_TYPE,
    profile: 'application/json+EDV Document',
    epochs: [{ id: `epoch-${epoch}`, recipients }]
  }
}

async function makeSigner() {
  const key = await Ed25519VerificationKey.generate()
  const keySigner = key.didKeySigner()
  return {
    keyMultibase: key.publicKeyMultibase,
    signer: {
      keyMultibase: key.publicKeyMultibase,
      async sign({ data }) {
        return keySigner.sign({ data })
      }
    }
  }
}

async function buildLog({ entries: count, recipients, signer, controller }) {
  const genesis = await buildResourceLogGenesis({
    state: descriptorState({ epoch: 1, count: recipients }),
    method: METHOD,
    controller,
    signer
  })
  const entries = [genesis]
  for (let index = 1; index < count; index++) {
    entries.push(
      await buildResourceLogEntry({
        head: entries[index - 1],
        state: descriptorState({ epoch: index + 1, count: recipients }),
        controller,
        signer
      })
    )
  }
  return entries
}

/**
 * Runs `run` RUNS times after one discarded warm-up; returns the mean wall
 * time and the last result.
 */
async function timed(run) {
  await run()
  const samples = []
  let result
  for (let index = 0; index < RUNS; index++) {
    const start = performance.now()
    result = await run()
    samples.push(performance.now() - start)
  }
  const mean = samples.reduce((sum, sample) => sum + sample, 0) / samples.length
  return { mean, result }
}

const { keyMultibase, signer } = await makeSigner()
const controller = fakeController({
  versions: [{ versionId: '1-v1', keys: [keyMultibase] }]
})

function verify({ entries, previous }) {
  return verifyResourceLog({
    entries,
    controller,
    expectedMethod: METHOD,
    ...(previous === undefined ? {} : { pin: previous.pin, previous })
  })
}

console.log('entries\trecipients\tbytes\tfull ms\tresumed +1 ms\tresumed +0 ms')
for (const recipients of recipientCounts) {
  // Every log with this recipient count is a prefix of the longest one, so
  // the longest is signed once and sliced.
  const longest = await buildLog({
    entries: Math.max(...entryCounts),
    recipients,
    signer,
    controller
  })
  for (const count of entryCounts) {
    const entries = longest.slice(0, count)
    const bytes = Buffer.byteLength(serializeResourceLog(entries))
    const { mean: full, result: whole } = await timed(() => verify({ entries }))
    const allButLast = await verify({ entries: entries.slice(0, -1) })
    const { mean: plusOne } = await timed(() =>
      verify({ entries, previous: allButLast })
    )
    const { mean: plusZero } = await timed(() =>
      verify({ entries, previous: whole })
    )
    console.log(
      [
        count,
        recipients,
        bytes,
        full.toFixed(1),
        plusOne.toFixed(2),
        plusZero.toFixed(2)
      ].join('\t')
    )
  }
}
