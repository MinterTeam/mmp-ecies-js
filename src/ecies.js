import crypto from 'crypto';
// import { ec as EC } from 'elliptic';
import secp256k1 from 'secp256k1';
// const ec = new EC("secp256k1");

/**
 * AES-256 CBC encrypt
 * @param {Buffer} iv
 * @param {Buffer} key
 * @param {Buffer} plainText
 * @returns {Buffer} cipherText
 */
function aes256CbcEncrypt (iv, key, plainText) {
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    const firstChunk = cipher.update(plainText);
    const secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk]);
}

/**
 * AES-256 CBC decrypt
 * @param {Buffer} iv
 * @param {Buffer} key
 * @param {Buffer} cipherText
 * @returns {Buffer} plainText
 */
function aes256CbcDecrypt (iv, key, cipherText) {
    const cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    const firstChunk = cipher.update(cipherText);
    const secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk]);
}


/**
 * Generate a new valid private key. Will use crypto.randomBytes as source.
 * @return {Buffer} A 32-byte private key.
 * @function
 */
function generatePrivate() {
    let privateKey;
    do {
        privateKey = crypto.randomBytes(32);
    } while (!secp256k1.privateKeyVerify(privateKey));
    return privateKey;
}


/**
 * Compute the public key for a given private key.
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Buffer} A 33-byte public key.
 * @function
 */
function getPublicCompressed(privateKey) {
    assert(privateKey.length === 32, "Bad private key");
    assert(secp256k1.privateKeyVerify(privateKey), "Bad private key");
    return Buffer.from(secp256k1.publicKeyCreate(privateKey, true));
}


/**
 * Derive shared secret for given private and public keys.
 * @param {Buffer} privateKeyA - Sender's private key (32 bytes)
 * @param {Buffer} publicKeyB - Recipient's public key (65|33 bytes)
 * @return {Buffer} Derived shared secret (Px, 32 bytes) and rejects on bad key.
 */
function derive(privateKeyA, publicKeyB) {
    assert(Buffer.isBuffer(privateKeyA), "Bad private key");
    assert(Buffer.isBuffer(publicKeyB), "Bad public key");
    assert(privateKeyA.length === 32, "Bad private key");
    assert(secp256k1.privateKeyVerify(privateKeyA), "Bad private key");
    assert(publicKeyB.length === 65 || publicKeyB.length === 33, "Bad public key");
    if (publicKeyB.length === 65) {
        assert(publicKeyB[0] === 4, "Bad public key");
    }
    if (publicKeyB.length === 33) {
        assert(publicKeyB[0] === 2 || publicKeyB[0] === 3, "Bad public key");
    }

    // slice 33 bytes to 32 bytes
    return Buffer.from(ecdhUnsafe(publicKeyB, privateKeyA)).slice(1);

    // var keyA = ec.keyFromPrivate(privateKeyA);
    // var keyB = ec.keyFromPublic(publicKeyB);
    // var Px = keyA.derive(keyB.getPublic());  // BN instance
    // return Buffer.from(Px.toArray());

    // get X point of ecdh
    // unsafe means no KDF, KDF will be applied later as sha512
    // https://github.com/cryptocoinjs/secp256k1-node#get-x-point-of-ecdh
    function ecdhUnsafe (publicKeyB, privateKeyA) {
        const ecdhPointX = secp256k1.ecdh(publicKeyB, privateKeyA, { hashfn }, Buffer.alloc(33));
        return ecdhPointX;
    }

    function hashfn (x, y) {
        const pubKey = new Uint8Array(33)
        pubKey[0] = (y[31] & 1) === 0 ? 0x02 : 0x03
        pubKey.set(x, 1)
        return pubKey
    }
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message || "Assertion failed");
    }
}

function sha512(msg) {
    return crypto.createHash("sha512").update(msg).digest();
}


/**
 * ECIES encrypt
 * @param {Buffer|Uint8Array} publicKeyTo Recipient's public key, compressed 33 bytes or uncompressed 65 bytes
 * @param {Buffer} plainText Plaintext to be encrypted
 * @param {Buffer} iv Initialization vector (16 bytes)
 * @param {?{?ephemeralPrivateKey: Buffer}} options
 * optional ephemeral key (32 bytes)
 * @returns {{publicKey: Buffer, cipherText: Buffer}}
 */
export function encrypt (publicKeyTo, plainText, iv, options) {
    options = options || {};
    if (options.ephemeralPrivateKey) {
        console.warn('Attention! Reusing private keys for encryption is security vulnerable. Never do it in production!')
        assert(secp256k1.privateKeyVerify(options.ephemeralPrivateKey), "Bad private key");
    }
    const ephemeralPrivateKey = options.ephemeralPrivateKey || generatePrivate();
    const ephemeralPublicKeyCompressed = getPublicCompressed(ephemeralPrivateKey);

    // ECDH to get shared secret
    const px = derive(ephemeralPrivateKey, publicKeyTo)
    // KDF from shared secret
    const hash = sha512(px);
    const encryptionKey = hash.slice(0, 32);
    // symmetric cipher
    const cipherText = aes256CbcEncrypt(iv, encryptionKey, plainText);

    return {
        publicKey: ephemeralPublicKeyCompressed, // 33 bytes
        cipherText,
    }
}

/**
 * ECIES decrypt
 * @param {Buffer} privateKeyTo Recipient's private key, 32 bytes
 * @param {Buffer} publicKeyFrom Sender's public key, 33 bytes or 65 bytes
 * @param {Buffer} cipherText Encrypted message, serialized, 33+ bytes
 * @param {Buffer} iv (16 bytes)
 * @returns {Buffer} plainText
 */
export function decrypt (privateKeyTo, publicKeyFrom, cipherText, iv) {
    // ECDH to get shared secret
    const px = derive(privateKeyTo, publicKeyFrom);
    // KDF from shared secret
    const hash = sha512(px);
    const encryptionKey = hash.slice(0, 32);
    // symmetric cipher
    const plainText = aes256CbcDecrypt(iv, encryptionKey, cipherText);
    return plainText;
}
