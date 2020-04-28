import React from 'react';
import { StyleSheet, Text, View } from 'react-native';

import RNSimpleCrypto from "react-native-simple-crypto";

async function Test() {
  // -- AES ------------------------------------------------------------- //
  const message = "data to encrypt";
  const messageArrayBuffer = RNSimpleCrypto.utils.convertUtf8ToArrayBuffer(
    message
  );

  const keyArrayBuffer = await RNSimpleCrypto.utils.randomBytes(32);
  console.log("randomBytes key", keyArrayBuffer);

  const ivArrayBuffer = await RNSimpleCrypto.utils.randomBytes(16);
  console.log("randomBytes iv", ivArrayBuffer);

  const cipherTextArrayBuffer = await RNSimpleCrypto.AES.encrypt(
    messageArrayBuffer,
    keyArrayBuffer,
    ivArrayBuffer
  );
  console.log("AES encrypt", cipherTextArrayBuffer);

  const decryptedArrayBuffer = await RNSimpleCrypto.AES.decrypt(
    cipherTextArrayBuffer,
    keyArrayBuffer,
    ivArrayBuffer
  );
  const decrypted = RNSimpleCrypto.utils.convertArrayBufferToUtf8(
   decryptedArrayBuffer
  );
  console.log("AES decrypt", decrypted);

  // -- HMAC ------------------------------------------------------------ //

  const keyHmac = await RNSimpleCrypto.utils.randomBytes(32);
  const signatureArrayBuffer = await RNSimpleCrypto.HMAC.hmac256(message, keyHmac);

  const signatureHex = RNSimpleCrypto.utils.convertArrayBufferToHex(
    signatureArrayBuffer
  );
  console.log("HMAC signature", signatureHex);

  // -- SHA ------------------------------------------------------------- //

  const sha1Hash = await RNSimpleCrypto.SHA.sha1("test");
  console.log("SHA1 hash", hash);

  const sha256Hash = await RNSimpleCrypto.SHA.sha1("test");
  console.log("SHA256 hash", sha256Hash);

  const sha512Hash = await RNSimpleCrypto.SHA.sha1("test");
  console.log("SHA512 hash", sha512Hash);

  // -- PBKDF2 ---------------------------------------------------------- //

  const password = "secret password";
  const salt = RNSimpleCrypto.utils.randomBytes(8);
  const iterations = 4096;
  const keyInBytes = 32;
  const hash = "SHA1";
  const passwordKey = await RNSimpleCrypto.PBKDF2.hash(
    password,
    salt,
    iterations,
    keyInBytes,
    hash
  );
  console.log("PBKDF2 passwordKey", passwordKey);

  // -- RSA ------------------------------------------------------------ //

  const rsaKeys = await RNSimpleCrypto.RSA.generateKeys(1024);
  console.log("RSA1024 private key", rsaKeys.private);
  console.log("RSA1024 public key", rsaKeys.public);

  const rsaEncryptedMessage = await RNSimpleCrypto.RSA.encrypt(
    message,
    rsaKeys.public
  );
  console.log("rsa Encrypt:", rsaEncryptedMessage);

  const rsaSignature = await RNSimpleCrypto.RSA.sign(
    rsaEncryptedMessage,
    rsaKeys.private,
    "SHA256"
  );
  console.log("rsa Signature:", rsaSignature);

  const validSignature = await RNSimpleCrypto.RSA.verify(
    rsaSignature,
    rsaEncryptedMessage,
    rsaKeys.public,
    "SHA256"
  );
  console.log("rsa signature verified:", validSignature);

  const rsaDecryptedMessage = await RNSimpleCrypto.RSA.decrypt(
    rsaEncryptedMessage,
    rsaKeys.private
  );
  console.log("rsa Decrypt:", rsaDecryptedMessage);
}

export default function App() {
  Test();
  return (
    <View style={styles.container}>
      <Text>Open up App.tsx to start working on your app!</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
});
