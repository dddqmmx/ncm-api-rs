// Regenerate independent known-answer vectors from the upstream Node implementation.
// Usage: node scripts/xeapi-node-fixtures.cjs <api-enhanced/util/crypto.js> <package.json for Node deps>
const fs = require('node:fs')
const vm = require('node:vm')
const crypto = require('node:crypto')
const zlib = require('node:zlib')
const { createRequire } = require('node:module')
const dependencyRequire = createRequire(process.argv[3])
const rawPrivate = (raw) => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), raw]), format: 'der', type: 'pkcs8' })
const serverSecret = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 101))
const serverPrivate = rawPrivate(serverSecret)
const serverPublic = crypto.createPublicKey(serverPrivate).export({ format: 'der', type: 'spki' }).subarray(-32)
const entropy = Buffer.from(Array.from({ length: 76 }, (_, i) => i))
entropy[16] = 27
const ephemeralPrivate = rawPrivate(entropy.subarray(32, 64))
const fixedRandom = [entropy.subarray(0, 16), entropy.subarray(16, 32), entropy.subarray(64, 76)]
const randomCrypto = { ...crypto, randomBytes: (length) => {
  const value = fixedRandom.shift()
  if (value.length !== length) throw new Error('unexpected random call')
  return value
}, generateKeyPairSync: () => ({ privateKey: ephemeralPrivate, publicKey: crypto.createPublicKey(ephemeralPrivate) }) }
const moduleObject = { exports: {} }
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), {
  module: moduleObject, exports: moduleObject.exports, Buffer, TextDecoder, URL, URLSearchParams,
  require: (name) => name === 'crypto' ? randomCrypto : name === './zstd' ? {} : dependencyRequire(name),
})
const upstream = moduleObject.exports
const publicKey = { publicKey: serverPublic.toString('base64'), version: '20261106', sk: 'synthetic-test-key' }
const data = { encodeType: 'flac', ids: '[3394877950]', level: 'hires' }
const encrypt = (key, bytes) => {
  const cipher = crypto.createCipheriv(`aes-${key.length * 8}-ecb`, key, null)
  return Buffer.concat([cipher.update(bytes), cipher.final()])
}
const response = { code: 200, data: [{ id: 3394877950, level: 'hires', url: 'https://fixture.invalid/song.flac', freeTrialInfo: null }] }
const staticKey = Buffer.from('ab1d5a430f6bb04a3f01e81ddd72bd916d5ce591248ac128714806d7f8fb1b84', 'hex')
const fixture = {
  upstream: 'NeteaseCloudMusicApiEnhanced/api-enhanced@4a7d557326d16d2f1e5172ee69c9471eb3a50173',
  entropy: [...entropy], serverSecret: [...serverSecret], publicKey, data,
  request: upstream.xeapi('/api/song/enhance/player/url/v1', data, { publicKeyState: publicKey }),
  sign: upstream.xeapiSign('1794492360000', '0123456789012345'),
  encryptedKey: encrypt(staticKey, Buffer.from(JSON.stringify(publicKey))).toString('base64'),
  response,
  encryptedResponse: encrypt(Buffer.from('e82ckenh8dichen8'), Buffer.from(JSON.stringify(response))).toString('base64'),
  compressedResponse: encrypt(Buffer.from('e82ckenh8dichen8'), zlib.gzipSync(Buffer.from(JSON.stringify(response)))).toString('base64'),
}
fixedRandom.push(entropy.subarray(16, 32), entropy.subarray(64, 76))
fixture.sessionRequest = upstream.xeapi('/api/song/enhance/player/url/v1', data, {
  publicKeyState: publicKey, sessionId: 'fixture-session', sessionKey: '0123456789abcdef',
})
process.stdout.write(JSON.stringify(fixture, null, 2) + '\n')
