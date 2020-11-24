var EC = require("elliptic").ec;
var ec = new EC("secp256k1");
const ecies = require("eth-ecies");

/**
 * @param {Object} options
 * @param {Buffer} options.privateKeyRecipient
 * @param {Buffer} options.privateKeySender
 * @param {string} options.plainText
 * @param {Buffer} options.iv
 * @return {Promise<{iv: Buffer, ephemeralPublicKey: Buffer, cipherText: Buffer, mac: Buffer}>}
 */
export default function ({privateKeyRecipient, privateKeySender, plainText, iv}) {
    const recipientPublicKey = getPublic(privateKeyRecipient);
    const recipientPublicKeyEth = recipientPublicKey.slice(1);

    return new Promise((resolve) => {
        let encrypted = ecies.encrypt(recipientPublicKeyEth, new Buffer(plainText, 'utf8'), {
            iv,
            ephemPrivKey: privateKeySender,
        });

        const decryptedPlainTextBuffer = ecies.decrypt(privateKeyRecipient, encrypted);
        if (plainText !== decryptedPlainTextBuffer.toString('utf8')) {
            throw new Error('encrypted and decrypted texts differ')
        }

        resolve({
            iv: encrypted.slice(0, 16).toString('hex'),
            ephemeralPublicKey: encrypted.slice(16, 81).toString('hex'),
            cipherText: encrypted.slice(113).toString('hex'),
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
