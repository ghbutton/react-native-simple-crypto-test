import React from "react";
import { StyleSheet, Text, View } from "react-native";

import RNSimpleCrypto from "react-native-simple-crypto";

async function Test() {
  const toHex = RNSimpleCrypto.utils.convertArrayBufferToHex;
  const toUtf8 = RNSimpleCrypto.utils.convertArrayBufferToUtf8;

  // -- AES ------------------------------------------------------------- //
  const message = "data to encrypt";
  const messageArrayBuffer = RNSimpleCrypto.utils.convertUtf8ToArrayBuffer(
    message
  );

  const keyArrayBuffer = await RNSimpleCrypto.utils.randomBytes(32);
  console.log("randomBytes key", toHex(keyArrayBuffer));

  const ivArrayBuffer = await RNSimpleCrypto.utils.randomBytes(16);
  console.log("randomBytes iv", toHex(ivArrayBuffer));

  const cipherTextArrayBuffer = await RNSimpleCrypto.AES.encrypt(
    messageArrayBuffer,
    keyArrayBuffer,
    ivArrayBuffer
  );
  console.log("AES encrypt", toHex(cipherTextArrayBuffer));

  const decryptedArrayBuffer = await RNSimpleCrypto.AES.decrypt(
    cipherTextArrayBuffer,
    keyArrayBuffer,
    ivArrayBuffer
  );
  console.log("AES decrypt", toUtf8(decryptedArrayBuffer));
  if (toUtf8(decryptedArrayBuffer) !== message) {
    console.error("AES decrypt returned unexpected results");
  }

  // -- HMAC ------------------------------------------------------------ //

  const keyHmac = await RNSimpleCrypto.utils.randomBytes(32);
  const signatureArrayBuffer = await RNSimpleCrypto.HMAC.hmac256(messageArrayBuffer, keyHmac);
  console.log("HMAC signature", toHex(signatureArrayBuffer));

  // -- SHA ------------------------------------------------------------- //

  const sha1Hash = await RNSimpleCrypto.SHA.sha1("test");
  console.log("SHA1 hash", sha1Hash);

  const sha256Hash = await RNSimpleCrypto.SHA.sha256("test");
  console.log("SHA256 hash", sha256Hash);

  const sha512Hash = await RNSimpleCrypto.SHA.sha512("test");
  console.log("SHA512 hash", sha512Hash);

  const arrayBufferToHash = RNSimpleCrypto.utils.convertUtf8ToArrayBuffer("test");
  const sha1ArrayBuffer = await RNSimpleCrypto.SHA.sha1(arrayBufferToHash);
  console.log("SHA1 hash bytes", toHex(sha1ArrayBuffer));

  if (toHex(sha1ArrayBuffer) !== sha1Hash) {
    console.error("SHA1 result mismatch!");
  }

  const sha256ArrayBuffer = await RNSimpleCrypto.SHA.sha256(arrayBufferToHash);
  console.log("SHA256 hash bytes", toHex(sha256ArrayBuffer));
  if (toHex(sha256ArrayBuffer) !== sha256Hash) {
    console.error("SHA256 result mismatch!");
  }

  const sha512ArrayBuffer = await RNSimpleCrypto.SHA.sha512(arrayBufferToHash);
  console.log("SHA512 hash bytes", toHex(sha512ArrayBuffer));
  if (toHex(sha512ArrayBuffer) !== sha512Hash) {
    console.error("SHA512 result mismatch!");
  }

  // -- PBKDF2 ---------------------------------------------------------- //

  const password = "secret password";
  const salt = "my-salt";
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
  console.log("PBKDF2 passwordKey", toHex(passwordKey));

  const passwordKeyArrayBuffer = await RNSimpleCrypto.PBKDF2.hash(
    RNSimpleCrypto.utils.convertUtf8ToArrayBuffer(password),
    RNSimpleCrypto.utils.convertUtf8ToArrayBuffer(salt),
    iterations,
    keyInBytes,
    hash
  );
  console.log("PBKDF2 passwordKey bytes", toHex(passwordKeyArrayBuffer));

  if (toHex(passwordKeyArrayBuffer) !== toHex(passwordKey)) {
    console.error("PBKDF2 result mismatch!");
  }

  const password2 = messageArrayBuffer;
  const salt2 = await RNSimpleCrypto.utils.randomBytes(8);
  const iterations2 = 10000;
  const keyInBytes2 = 32;
  const hash2 = "SHA256";

  const passwordKey2 = await RNSimpleCrypto.PBKDF2.hash(
    password2,
    salt2,
    iterations2,
    keyInBytes2,
    hash2
  );
  console.log("PBKDF2 passwordKey2", toHex(passwordKey2));

  // -- RSA ------------------------------------------------------------ //

  const rsaKeys = await RNSimpleCrypto.RSA.generateKeys(1024);
  console.log("RSA1024 private key", rsaKeys.private);
  console.log("RSA1024 public key", rsaKeys.public);

  // UTF-8
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

  // UTF-8
  const rsaDecryptedMessage = await RNSimpleCrypto.RSA.decrypt(
    rsaEncryptedMessage,
    rsaKeys.private
  );
  console.log("rsa Decrypt:", rsaDecryptedMessage);
  if (rsaDecryptedMessage !== message) {
    console.error("RSA decrypt returned unexpected result");
  }


  // Base64
  const binaryData = "Zm9vYmFy";
  const rsaEncryptedMessage64 = await RNSimpleCrypto.RSA.encrypt64(
    binaryData,
    rsaKeys.public
  );
  console.log("rsa Encrypt 64:", rsaEncryptedMessage64);

  // Base 64
  const rsaDecryptedMessage64 = await RNSimpleCrypto.RSA.decrypt64(
    rsaEncryptedMessage64,
    rsaKeys.private
  );
  console.log("rsa Decrypt 64:", rsaDecryptedMessage64);
  if (rsaDecryptedMessage64 !== binaryData) {
    console.error("RSA 64 decrypt returned unexpected result");
  }
}

export default function App() {
  void Test().catch(console.error);

  return (
    <View style={styles.container}>
      <Text>Check the console for debug output</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
    alignItems: "center",
    justifyContent: "center",
  },
});
