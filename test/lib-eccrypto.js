var eccrypto = require("eccrypto");


/**
 * @param {Object} options
 * @param {Buffer} options.privateKeyRecipient
 * @param {Buffer} options.privateKeySender
 * @param {string} options.plainText
 * @param {Buffer} options.iv
 * @return {Promise<{iv: Buffer, ephemeralPublicKey: Buffer, cipherText: Buffer, mac: Buffer}>}
 */
export default function ({privateKeyRecipient, privateKeySender, plainText, iv}) {
    const recipientPublicKey = eccrypto.getPublic(privateKeyRecipient);

    return new Promise((resolve) => {
        eccrypto.encrypt(recipientPublicKey, new Buffer(plainText, 'utf8'), {
            iv,
            ephemPrivateKey: privateKeySender,
        }).then(function(encrypted) {
            eccrypto.decrypt(privateKeyRecipient, encrypted)
                .then(function(decryptedPlainTextBuffer) {
                    if (plainText !== decryptedPlainTextBuffer.toString('utf8')) {
                        throw new Error('encrypted and decrypted texts differ')
                    }
                    resolve({
                        iv: encrypted.iv.toString('hex'),
                        ephemeralPublicKey: encrypted.ephemPublicKey.toString('hex'),
                        cipherText: encrypted.ciphertext.toString('hex'),
                    });
                });
        });
    });
}
