var EC = require("elliptic").ec;
var ec = new EC("secp256k1");
const secp256k1 = require('secp256k1');
const ecies = require("../src/ecies.js");

/**
 * @param {Object} options
 * @param {Buffer} options.privateKeyRecipient
 * @param {Buffer} options.privateKeySender
 * @param {string} options.plainText
 * @param {Buffer} options.iv
 * @return {Promise<{iv: Buffer, ephemeralPublicKey: Buffer, cipherText: Buffer, mac: Buffer}>}
 */
export default function ({privateKeyRecipient, privateKeySender, plainText, iv}) {
    const publicKeyRecipient = getPublic(privateKeyRecipient);

    return new Promise((resolve) => {
        let {publicKey: publicKeySender, cipherText} = ecies.encrypt(publicKeyRecipient, new Buffer(plainText, 'utf8'), iv, {
            ephemeralPrivateKey: privateKeySender,
        });

        const decryptedPlainTextBuffer = ecies.decrypt(privateKeyRecipient, publicKeySender, cipherText, iv);
        if (plainText !== decryptedPlainTextBuffer.toString('utf8')) {
            throw new Error('encrypted and decrypted texts differ')
        }

        resolve({
            iv: iv.toString('hex'),
            ephemeralPublicKey: Buffer.from(secp256k1.publicKeyConvert(publicKeySender, false)).toString('hex'),
            cipherText: cipherText.toString('hex'),
        });
    });
}

/**
 * Compute the public key for a given private key.
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Buffer} A 65-byte public key.
 * @function
 */
function getPublic(privateKey) {
    // XXX(Kagami): `elliptic.utils.encode` returns array for every
    // encoding except `hex`.
    return Buffer.from(ec.keyFromPrivate(privateKey).getPublic("arr"));
};
