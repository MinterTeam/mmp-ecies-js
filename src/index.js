import {encrypt as eciesEncrypt, decrypt as eciesDecrypt} from './ecies.js';

/**
 * Make 16 bytes padded Buffer from iv string
 * @param {string|Buffer} iv
 * @returns {Buffer}
 */
export function ivToBuffer(iv) {
    if (typeof iv === 'string') {
        iv = Buffer.from(iv, 'utf8');
    }
    const result = Buffer.alloc(16);
    iv.copy(result, 0, 0, 16);

    return result;
}

/**
 * ECIES encrypt
 * Makes Buffer only implementation string friendly
 * @param {string|Buffer|Uint8Array} publicKeyTo Recipients public key, compressed 33 bytes or uncompressed 65 bytes, may be hex string
 * @param {string|Buffer} plainText Plaintext to be encrypted, UTF8 or Buffer
 * @param {string|Buffer} iv, UTF8 or Buffer
 * @param {?{?ephemeralPrivateKey: string|Buffer}} options
 * optional ephemeral key (32 bytes)
 * @returns {Buffer} Encrypted message, serialized, ready to send in payload
 */
export function encrypt(publicKeyTo, plainText, iv, options= {}) {
    // hex to Buffer
    if (typeof publicKeyTo === 'string') {
        publicKeyTo = publicKeyTo.replace('0x', '').replace('0X', '');
        publicKeyTo = Buffer.from(publicKeyTo, 'hex');
    } else {
        // ensure Buffer (convert Array or Uint8Array)
        publicKeyTo = Buffer.from(publicKeyTo);
    }

    // hex to Buffer
    if (options.ephemeralPrivateKey && typeof publicKeyTo === 'string') {
        options.ephemeralPrivateKey = options.ephemeralPrivateKey.replace('0x', '').replace('0X', '');
        options.ephemeralPrivateKey = Buffer.from(options.ephemeralPrivateKey, 'hex');
    }

    // utf8 to Buffer
    const ivBuffer = ivToBuffer(iv);

    // utf8 to Buffer
    if (typeof plainText === 'string') {
        plainText = Buffer.from(plainText, 'utf8');
    }

    const result = eciesEncrypt(publicKeyTo, plainText, ivBuffer, options);

    return Buffer.concat([
        Buffer.from(iv + ' ', 'utf8'),
        result.publicKey,
        result.cipherText,
    ]);
}

/**
 * ECIES decrypt
 * Makes Buffer only implementation string friendly
 * @param {string|Buffer} privateKey Recipient's private key, 32 bytes, hex string or Buffer
 * @param {Buffer} payload Encrypted message, serialized binary data from payload
 * @returns {string} plainText UTF8
 */
export function decrypt(privateKey, payload) {
    // hex to Buffer
    if (typeof privateKey === 'string') {
        privateKey = privateKey.replace('0x', '').replace('0X', '');
        privateKey = Buffer.from(privateKey, 'hex');
    }

    const payloadString = Buffer.from(payload).toString('utf8')
    const ivMatch = /^mmp\d+\.\d+\.\d+/.exec(payloadString);
    if (!ivMatch || ivMatch.length === 0) {
        throw new Error('Payload doesn\'t contain "mmpX.X.X" prefix');
    }
    let iv = ivMatch[0];

    // remove mmp prefix and space delimiter, e.g. "mmp0.0.1 "
    const encrypted = payload.slice(iv.length + 1);

    // utf8 to Buffer
    iv = ivToBuffer(iv);

    const PUBLIC_KEY_LENGTH = 33;
    // read ephemeralPublicKey and cipherText from encrypted message
    const publicKeyFrom = Buffer.from(encrypted.slice(0, PUBLIC_KEY_LENGTH));
    const cipherText = encrypted.slice(PUBLIC_KEY_LENGTH);

    const plainTextBuffer = eciesDecrypt(privateKey, publicKeyFrom, cipherText, iv);

    return plainTextBuffer.toString('utf8');
}
