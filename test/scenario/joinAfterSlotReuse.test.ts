import { ClientState, createGroup, joinGroup, makePskIndex } from "../../src/clientState.js"
import { createCommit } from "../../src/createCommit.js"
import { processPrivateMessage } from "../../src/processMessages.js"
import { emptyPskIndex } from "../../src/pskIndex.js"
import { CiphersuiteImpl, CiphersuiteName, ciphersuites, getCiphersuiteFromName } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { generateKeyPackage, KeyPackage, PrivateKeyPackage } from "../../src/keyPackage.js"
import { Proposal } from "../../src/proposal.js"
import { testEveryoneCanMessageEveryone } from "./common.js"
import { defaultLifetime } from "../../src/lifetime.js"
import { defaultCapabilities } from "../../src/defaultCapabilities.js"

test.concurrent.each(Object.keys(ciphersuites))(`Join after a removed member's leaf is reused %s`, async (cs) => {
  await joinAfterSlotReuse(cs as CiphersuiteName)
})

// A new member's leaf goes into a blank slot below a parent another member's path filled, then a
// different member adds one more. RFC 9420 section 12.4.3.1 asks only that each unmerged leaf is
// listed by the non-blank nodes between it and the parent that lists it.
async function joinAfterSlotReuse(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))
  const packages: { publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }[] = []
  for (let i = 0; i < 7; i++) {
    const credential = { credentialType: "basic" as const, identity: new TextEncoder().encode(`member${i}`) }
    packages.push(await generateKeyPackage(credential, defaultCapabilities(), defaultLifetime, [], impl))
  }

  const groups = new Map<number, ClientState>()
  groups.set(
    0,
    await createGroup(
      new TextEncoder().encode("group1"),
      packages[0]!.publicPackage,
      packages[0]!.privatePackage,
      [],
      impl,
    ),
  )

  await commit(groups, impl, 0, [add(packages[1]!)], [1], packages)
  await commit(groups, impl, 1, [add(packages[2]!)], [2], packages)
  await commit(groups, impl, 0, [add(packages[3]!), add(packages[4]!)], [3, 4], packages)
  await commit(
    groups,
    impl,
    1,
    [{ proposalType: "remove", remove: { removed: groups.get(3)!.privatePath.leafIndex } }],
    [],
    packages,
  )
  groups.delete(3)
  await commit(groups, impl, 2, [add(packages[5]!)], [5], packages)
  await commit(groups, impl, 0, [add(packages[6]!)], [6], packages)

  await testEveryoneCanMessageEveryone([...groups.values()], impl)
}

function add(p: { publicPackage: KeyPackage }): Proposal {
  return { proposalType: "add", add: { keyPackage: p.publicPackage } }
}

async function commit(
  groups: Map<number, ClientState>,
  impl: CiphersuiteImpl,
  committer: number,
  proposals: Proposal[],
  joiners: number[],
  packages: { publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }[],
) {
  const result = await createCommit(
    { state: groups.get(committer)!, cipherSuite: impl },
    { extraProposals: proposals, ratchetTreeExtension: true },
  )
  if (result.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")
  for (const [i, state] of groups) {
    if (i === committer) continue
    const processed = await processPrivateMessage(state, result.commit.privateMessage, makePskIndex(state, {}), impl)
    groups.set(i, processed.newState)
  }
  groups.set(committer, result.newState)
  for (const j of joiners) {
    groups.set(
      j,
      await joinGroup(result.welcome!, packages[j]!.publicPackage, packages[j]!.privatePackage, emptyPskIndex, impl),
    )
  }
}
