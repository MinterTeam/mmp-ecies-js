import secp256k1 from 'secp256k1';
import {encrypt, decrypt} from '~/src/index.js';

const iv = 'mmp0.0.1';
const privateKeySender = Buffer.from('287be0b7a5ea467bed2970868f443263169b79c2c3176ca1483b256e36e5c340', 'hex');
const privateKeyRecipient = Buffer.from('dc03b2c47c40cab2cfbc382b30264bc78b46a3dce1eb8d449fe4f56c3a1ebb35', 'hex');
const VALID_PLAIN_TEXT = 'Plain text message to encrypt';
const VALID_CIPHER_TEXT = '58e67e899c3f69e8852dade667e668e18fe4cec755cc656479888ef7fae2b69c';

test('encrypt', () => {
    const publicKeyRecipient = secp256k1.publicKeyCreate(privateKeyRecipient);
    const serialized = encrypt(publicKeyRecipient, VALID_PLAIN_TEXT, iv, {ephemeralPrivateKey: privateKeySender});
    // remove prefix (8), space delimiter (1), and public key (33) from serialized data
    const cipherText = serialized.slice(8 + 1 + 33).toString('hex');
    expect(cipherText).toEqual(VALID_CIPHER_TEXT);
})

test('decrypt', () => {
    const publicKeySender = secp256k1.publicKeyCreate(privateKeySender, true);
    const payload = Buffer.concat([
        Buffer.from(iv + ' ', 'utf8'),
        publicKeySender,
        Buffer.from(VALID_CIPHER_TEXT, 'hex')
    ]);
    const plainText = decrypt(privateKeyRecipient, payload);
    expect(plainText).toEqual(VALID_PLAIN_TEXT);
})






