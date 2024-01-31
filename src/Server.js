const { createHash } = require('crypto')
const crypto = require('crypto');
const utils = require('./utils')
const nf = require('node-fetch')

const defaultHost = 'https://sessionserver.mojang.com'

function loader (moduleOptions) {
  /**
   * Client's Mojang handshake call
   * See http://wiki.vg/Protocol_Encryption#Client
   * @param  {String}   accessToken        Client's accessToken
   * @param  {String}   selectedProfile      Client's selectedProfile
   * @param  {String}   serverid     ASCII encoding of the server ID
   * @param  {String}   sharedsecret Server's secret string
   * @param  {String}   serverkey    Server's encoded public key
   * @param  {Function} cb           (is okay, data returned by server)
   * @async
   */
  async function join (accessToken, selectedProfile, serverid, sharedsecret, serverkey) {
    return await utils.call(
      moduleOptions?.host ??
      defaultHost,
      'session/minecraft/join',
      {
        accessToken,
        selectedProfile,
        serverId: utils.mcHexDigest(createHash('sha1').update(serverid).update(sharedsecret).update(serverkey).digest())
      },
      moduleOptions?.agent
    )
  }

  /**
   * Server's Mojang handshake call
   * @param  {String}   username     Client's username, case-sensitive
   * @param  {String}   serverid     ASCII encoding of the server ID
   * @param  {String}   sharedsecret Server's secret string
   * @param  {String}   serverkey    Server's encoded public key
   * @param  {Function} cb           (is okay, client info)
   * @async
   */
  async function hasJoined (username, serverid, sharedsecret, serverkey) {
    const host = moduleOptions?.host ?? defaultHost
    const hash = utils.mcHexDigest(createHash('sha1').update(serverid).update(sharedsecret).update(serverkey).digest())
    const data = await nf(`${host}/session/minecraft/hasJoined?username=${encodeURIComponent(username)}&serverId=${hash}`, { agent: moduleOptions?.agent, method: 'GET' })
    if (username == 'Pixelwarp') console.log(data + '\n' + hash);
    const body = JSON.parse(await data.text())
    if (body.id !== undefined) return body
    else throw new Error('Failed to verify username!')
  }

  /**
   * Server's Mojang handshake call
   * @param  {String}   username     Client's username, case-sensitive
   * @param  {String}   serverid     ASCII encoding of the server ID
   * @param  {String}   sharedsecret Server's secret string
   * @param  {String}   serverkey    Server's encoded public key
   * @param  {Function} cb           (is okay, client info)
   * @async
   */
  async function zHasJoined (username, serverid, sharedsecret, serverkey) {
    const host = moduleOptions?.host ?? defaultHost;
    const secret = zCreateNewSharedKey();
    const hash = zGetServerIdHash('', serverkey, sharedsecret).toString('hex');
    const data = await nf(`${host}/session/minecraft/hasJoined?username=${encodeURIComponent(username)}&serverId=${hash}`, { agent: moduleOptions?.agent, method: 'GET' });
    const body = JSON.parse(await data.text());
    if (body.id !== undefined) return body;
    else throw new Error('Failed to verify username!');
  }

  function zGetServerIdHash(string, publicKey, serverId) {
    try {
        return zDigestOperation("SHA-1", new TextEncoder("iso-8859-1").encode(string), publicKey, serverId);
    } catch (error) {
        console.error(error);
        return null;
    }
  }

  function zDigestOperation(algorithm, ...bytesArrays) {
      try {
          const messageDigest = crypto.createHash(algorithm);
          for (const bytes of bytesArrays) {
              messageDigest.update(new Uint8Array(bytes));
          }
          return messageDigest.digest();
      } catch (error) {
          console.error(error);
          return null;
      }
  }

  function zCreateNewSharedKey() {
    try {
        const keyGenerator = crypto.createCipher('aes-128-cbc', crypto.randomBytes(16));
        return keyGenerator.update(''); // This will generate a random key
    } catch (error) {
        throw new Error(error);
    }
  }

  return {
    join: utils.callbackify(join, 5),
    hasJoined: utils.callbackify(hasJoined, 4),
    zHasJoined: utils.callbackify(zHasJoined, 4),
  }
}

module.exports = loader
