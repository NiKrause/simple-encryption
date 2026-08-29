import { strictEqual, notStrictEqual } from 'assert'
import SimpleEncryption from '../src/index.js'

describe('Initialization Vector', function () {
  this.timeout(45000)

  it('never repeats a nonce under one key', async function () {
    const encryption = await SimpleEncryption({ password: 'hello' })
    const nonces = new Set()
    const count = 2000

    for (let i = 0; i < count; i++) {
      const encrypted = await encryption.encrypt(new TextEncoder().encode('world' + i))
      nonces.add(encrypted.subarray(16, 28).toString())
    }

    strictEqual(nonces.size, count, 'every message must carry its own nonce')
  })

  it('round-trips every message', async function () {
    const encryption = await SimpleEncryption({ password: 'hello' })

    for (let i = 0; i < 500; i++) {
      const encrypted = await encryption.encrypt(new TextEncoder().encode('world' + i))
      const decrypted = await encryption.decrypt(encrypted)
      strictEqual(new TextDecoder().decode(decrypted), 'world' + i)
    }
  })

  it('derives a new salt at the configured interval', async function () {
    const encryption = await SimpleEncryption({ password: 'hello' })
    const { ivInterval } = encryption

    // Drive the counter directly rather than encrypting ivInterval times: the
    // rotation is what is under test, not the throughput to reach it.
    const first = await encryption.encrypt(new TextEncoder().encode('a'))
    const saltBefore = first.subarray(0, 16).toString()

    let last = first
    for (let i = 1; i <= ivInterval; i++) {
      last = await encryption.encrypt(new TextEncoder().encode('b'), i)
      if (i < ivInterval) continue
    }

    notStrictEqual(last.subarray(0, 16).toString(), saltBefore, 'salt should rotate at the interval')
  })
})
