const nf = require('node-fetch')

const { version } = require('../package.json'); // eslint-disable-line

const headers = {
  'User-Agent': `node-yggdrasil/${version}`,
  'Content-Type': 'application/json'
}

/**
 * Generic POST request
 */
async function call (host, path, data, agent) {
  const resp = await nf(`${host}/${path}`, { agent, body: JSON.stringify(data), headers, method: 'POST' })
  let body = await resp.text()
  if (body.length === 0) return ''
  try {
    body = JSON.parse(body)
  } catch (e) {
    if (e instanceof SyntaxError) {
      if (resp.status === 403) {
        if ((body).includes('Request blocked.')) {
          throw new Error('Request blocked by CloudFlare')
        }
        if ((body).includes('cf-error-code">1009')) {
          throw new Error('Your IP is banned by CloudFlare')
        }
      } else {
        throw new Error(`Response is not JSON. Status code: ${resp.status ?? 'no status code'}`)
      }
    } else {
      throw e
    }
  }
  if (body?.error !== undefined) throw new Error(body?.errorMessage ?? body?.error)
  return body
}
/**
 * Java's stupid hashing method
 * @param  {Buffer|String} hash     The hash data to stupidify
 * @param  {String} encoding Optional, passed to Buffer() if hash is a string
 * @return {String}          Stupidified hash
 */
function mcHexDigest (hash, encoding) {
  if (!(hash instanceof Buffer)) {
    hash = (Buffer).from(hash, encoding)
  }
  // check for negative hashes
  const negative = (hash).readInt8(0) < 0
  if (negative) performTwosCompliment(hash)
  return (negative ? '-' : '') + hash.toString('hex').replace(/^0+/g, '')
}

function callbackify (f, maxParams) {
  return function (...args) {
    let cb
    let i = args.length
    while (cb === undefined && i > 0) {
      if (typeof args[i - 1] === 'function') {
        cb = args[i - 1]
        args[i - 1] = undefined
        args[maxParams] = cb
        break
      }
      i--
    }
    return f(...args).then(
      (r) => {
        if (r[0] !== undefined) {
          cb?.(undefined, ...r)
          return r[r.length - 1]
        } else {
          cb?.(undefined, r)
          return r
        }
      },
      (err) => {
        if (typeof cb === 'function') cb(err)
        else throw err
      }
    )
  }
}

/**
 * Java's annoying hashing method.
 * All credit to andrewrk
 * https://gist.github.com/andrewrk/4425843
 */
function performTwosCompliment (buffer) {
  let carry = true
  let i, newByte, value
  for (i = buffer.length - 1; i >= 0; --i) {
    value = buffer.readUInt8(i)
    newByte = ~value & 0xff
    if (carry) {
      carry = newByte === 0xff
      buffer.writeUInt8(carry ? 0 : newByte + 1, i)
    } else {
      buffer.writeUInt8(newByte, i)
    }
  }
}

const crypto = require('crypto');

class CryptManager {
  static LOGGER = console;

  static createNewSharedKey() {
    try {
      const sharedKey = crypto.randomBytes(16); // Generate a 128-bit (16-byte) random key
      return sharedKey;
    } catch (error) {
      throw new Error(error);
    }
  }

  static generateKeyPair() {
    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 1024,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
      });

      return { publicKey, privateKey };
    } catch (error) {
      console.error(error);
      CryptManager.LOGGER.error('Key pair generation failed!');
      return null;
    }
  }

  static getServerIdHash(string, serverId, publicKey) {
    try {
      return CryptManager.digestOperation(
        'sha1',
        Buffer.from(string, 'utf-8'),
        Buffer.from(publicKey, 'utf-8'),
        Buffer.from(serverId, 'utf-8')
      );
    } catch (error) {
      console.error(error);
      return null;
    }
  }

  static digestOperation(algorithm, ...data) {
    try {
      const messageDigest = crypto.createHash(algorithm);
      for (const cs of data) {
        messageDigest.update(cs);
      }
      return messageDigest.digest();
    } catch (error) {
      console.error(error);
      return null;
    }
  }

  static decodePublicKey(bs) {
    try {
      const keyFactory = crypto.createPublicKey(bs, { format: 'der', type: 'spki' });
      return keyFactory;
    } catch (error) {
      console.error(error);
      CryptManager.LOGGER.error('Public key reconstitute failed!');
      return null;
    }
  }

  static decryptSharedKey(privateKey, key) {
    const decryptedData = CryptManager.decryptData(privateKey, key);
    if (decryptedData) {
      return crypto.createCipheriv('aes-128-cbc', Buffer.alloc(16), Buffer.alloc(0)).update(decryptedData);
    }
    return null;
  }

  static encryptData(key, data) {
    return CryptManager.cipherOperation(1, key, data);
  }

  static decryptData(key, data) {
    return CryptManager.cipherOperation(2, key, data);
  }

  static cipherOperation(opMode, transformation, data) {
    try {
      const cipher = crypto.createCipheriv(transformation.algorithm, Buffer.alloc(16), Buffer.alloc(0));
      const result = opMode === 1 ? cipher.update(data) : cipher.update(data);
      return Buffer.concat([result, cipher.final()]);
    } catch (error) {
      console.error(error);
      CryptManager.LOGGER.error('Cipher data failed!');
      return null;
    }
  }

  static createTheCipherInstance(opMode, algorithm, transformation) {
    try {
      const cipher = crypto.createCipher(algorithm, Buffer.alloc(16));
      cipher.init(opMode, Buffer.alloc(16));
      return cipher;
    } catch (error) {
      console.error(error);
      CryptManager.LOGGER.error('Cipher creation failed!');
      return null;
    }
  }

  static createNetCipherInstance(opMode, transformation) {
    try {
      const cipher = crypto.createCipheriv('aes-128-cfb8', Buffer.alloc(16), Buffer.alloc(16));
      cipher.init(opMode, Buffer.alloc(16));
      return cipher;
    } catch (error) {
      throw new Error(error);
    }
  }
}

module.exports = {
  call: callbackify(call, 4),
  callbackify,
  CryptManager,
  mcHexDigest
}
