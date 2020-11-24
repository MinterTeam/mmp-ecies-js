import crypto from 'crypto';
import implEccrypto from './lib-eccrypto.js';
import implEthEcies from './lib-eth-ecies.js';
import implMmp from './lib-mmp.js';

var privateKeySender = crypto.randomBytes(32);
var privateKeyRecipient = crypto.randomBytes(32);

const plainText = 'Plain text message to encrypt';
let iv = Buffer.alloc(16);
Buffer.from('mmp0.0.1', 'utf8').copy(iv, 0, 0, 16);

test('eccrypto vs eth-ecies', async () => {
    const encryptedEccrypto = await implEccrypto({privateKeyRecipient, privateKeySender, plainText, iv});
    const encryptedEthEcies = await implEthEcies({privateKeyRecipient, privateKeySender, plainText, iv});

    expect(encryptedEccrypto).toEqual(encryptedEthEcies);
    console.log(privateKeySender.toString('hex'))
    console.log(privateKeyRecipient.toString('hex'))
    console.log(encryptedEthEcies.cipherText)
})

test('eccrypto vs mmp', async () => {
    const encryptedEccrypto = await implEccrypto({privateKeyRecipient, privateKeySender, plainText, iv});
    const encryptedMmp = await implMmp({privateKeyRecipient, privateKeySender, plainText, iv});

    expect(encryptedEccrypto).toEqual(encryptedMmp);
})
