import crypto from "crypto";
import secp256k1 from 'secp256k1';

/**
 * Generate a new valid private key. Will use crypto.randomBytes as source.
 * @return {Buffer} A 32-byte private key.
 * @function
 */
export function generatePrivate() {
    let privateKey;
    do {
        privateKey = crypto.randomBytes(32);
    } while (!secp256k1.privateKeyVerify(privateKey));
    return privateKey;
}
