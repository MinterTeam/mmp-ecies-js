import secp256k1 from 'secp256k1';
import {encrypt, decrypt} from '~/src/index.js';

describe('test', () => {
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
    });

    test('decrypt', () => {
        const publicKeySender = secp256k1.publicKeyCreate(privateKeySender, true);
        const payload = Buffer.concat([
            Buffer.from(iv + ' ', 'utf8'),
            publicKeySender,
            Buffer.from(VALID_CIPHER_TEXT, 'hex')
        ]);
        const plainText = decrypt(privateKeyRecipient, payload);
        expect(plainText).toEqual(VALID_PLAIN_TEXT);
    });
})

describe('full test', () => {
    const iv = 'mmp0.2.0';
    // sender (merchant)
    const privateKeySender = Buffer.from('408dd6c7dc7f3c67e3a4faffe2bef89ded6ebadbf9a7cc4f3beb63f527177c1a', 'hex');
    const publicKeySender = Buffer.from('029d016b219f43c54bea89e5edd8b253474e1eaf57d49da6bb8b853549fe03cb72', 'hex');
    // recipient (user)
    const privateKeyRecipient = Buffer.from('19d5721add309be440d94f60a90432f3f5b09f9c25ba2562fc39dcf73a95b138', 'hex');
    const publicKeyRecipient = Buffer.from('025fec64d8a61efbd830f90ac21a2b9fd3c44394dc416d60300e473bc431ccdef6', 'hex')
    const VALID_PLAIN_TEXT = '{m:"Plain text message to encrypt"}';
    const VALID_PAYLOAD = Buffer.from('6d6d70302e322e3020029d016b219f43c54bea89e5edd8b253474e1eaf57d49da6bb8b853549fe03cb72781e831536a0a611dbda1b0eee2e442b890fd176d12cd462d24d8c362a881c2467138520f5a30c10cf5776aea8b0b3ea', 'hex');

    test('publicKeyFrom compressed', () => {
        const publicKeyFrom = secp256k1.publicKeyCreate(privateKeySender, true);
        expect(Buffer.from(publicKeyFrom).toString('hex')).toEqual(publicKeySender.toString('hex'))
    });

    test('publicKeyTo compressed', () => {
        const publicKeyTo = secp256k1.publicKeyCreate(privateKeyRecipient, true);
        expect(Buffer.from(publicKeyTo).toString('hex')).toEqual(publicKeyRecipient.toString('hex'))
    });

    test('encrypt', () => {
        const payload = encrypt(publicKeyRecipient, VALID_PLAIN_TEXT, iv, {ephemeralPrivateKey: privateKeySender});

        expect(payload.toString('hex')).toEqual(VALID_PAYLOAD.toString('hex'));

        const prefixLength = iv.length;
        const prefix = payload.slice(0, prefixLength);
        expect(prefix.toString('utf8')).toEqual(iv);

        const spaceDelimiter = payload.slice(prefixLength, prefixLength + 1);
        expect(spaceDelimiter.toString('utf8')).toEqual(' ');

        const publicKeyFromCompressed = payload.slice(prefixLength + 1, prefixLength + 1 + 33);
        expect(publicKeyFromCompressed.toString('hex')).toEqual(publicKeySender.toString('hex'));
    });

    test('decrypt', () => {
        const plainText = decrypt(privateKeyRecipient, VALID_PAYLOAD);
        expect(plainText).toEqual(VALID_PLAIN_TEXT);
    });
})

