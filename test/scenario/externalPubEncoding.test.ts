import { createGroup, makePskIndex } from "../../src/clientState.js"
import {
  createGroupInfo,
  createGroupInfoWithExternalPubAndRatchetTree,
  joinGroupExternal,
} from "../../src/createCommit.js"
import { processPublicMessage } from "../../src/processMessages.js"
import { Credential } from "../../src/credential.js"
import { CiphersuiteImpl, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage } from "../../src/keyPackage.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { decodeVarLenData } from "../../src/codec/variableLength.js"
import { ratchetTreeEncoder } from "../../src/ratchetTree.js"
import { ClientState } from "../../src/clientState.js"

const credential = (name: string): Credential => ({ credentialType: "basic", identity: new TextEncoder().encode(name) })

async function group(impl: CiphersuiteImpl, id: Uint8Array) {
  const alice = await generateKeyPackage(credential("alice"), defaultCapabilities(), defaultLifetime, [], impl)
  return createGroup(id, alice.publicPackage, alice.privatePackage, [], impl)
}

async function externalPub(state: ClientState, impl: CiphersuiteImpl) {
  return impl.hpke.exportPublicKey((await impl.hpke.deriveKeyPair(state.keySchedule.externalSecret)).publicKey)
}

/** A GroupInfo the way 1.6.4 wrote it: the external key with no length in front. */
async function bareGroupInfo(state: ClientState, impl: CiphersuiteImpl) {
  return createGroupInfo(
    state.groupContext,
    state.confirmationTag,
    state,
    [
      { extensionType: "external_pub", extensionData: await externalPub(state, impl) },
      { extensionType: "ratchet_tree", extensionData: encode(ratchetTreeEncoder)(state.ratchetTree) },
    ],
    impl,
  )
}

async function joins(state: ClientState, groupInfo: Awaited<ReturnType<typeof bareGroupInfo>>, impl: CiphersuiteImpl) {
  const charlie = await generateKeyPackage(credential("charlie"), defaultCapabilities(), defaultLifetime, [], impl)
  const join = await joinGroupExternal(groupInfo, charlie.publicPackage, charlie.privatePackage, false, impl)
  const seen = await processPublicMessage(state, join.publicMessage, makePskIndex(state, {}), impl)
  expect(join.newState.keySchedule.epochAuthenticator).toStrictEqual(seen.newState.keySchedule.epochAuthenticator)
}

const suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" as const

test("external_pub is written as RFC 9420 HPKEPublicKey<V>", async () => {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(suite))
  const state = await group(impl, new TextEncoder().encode("rfc"))
  const gi = await createGroupInfoWithExternalPubAndRatchetTree(state, [], impl)
  const data = gi.extensions.find((e) => e.extensionType === "external_pub")!.extensionData
  const decoded = decodeVarLenData(data, 0)!
  expect(decoded[1]).toBe(data.length)
  expect(decoded[0]).toStrictEqual(await externalPub(state, impl))
  await joins(state, gi, impl)
})

test("a GroupInfo with 1.6.4's bare external_pub still lets a device join", async () => {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(suite))
  const state = await group(impl, new TextEncoder().encode("bare"))
  await joins(state, await bareGroupInfo(state, impl), impl)
})

test("a bare key that also parses as a shorter length-prefixed one still works", async () => {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(suite))
  // 0x1f is a one-byte length of 31, which the 31 bytes after it fill exactly.
  for (let i = 0; i < 4096; i++) {
    const state = await group(impl, new TextEncoder().encode(`ambiguous-${i}`))
    if ((await externalPub(state, impl))[0] !== 0x1f) continue
    await joins(state, await bareGroupInfo(state, impl), impl)
    return
  }
  throw new Error("no external key starting with 0x1f in 4096 groups")
})
