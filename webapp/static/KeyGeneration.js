// ECDH
async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-384'
    },
    true,
    ['deriveKey', 'deriveBits']
  );

  return keyPair;
}

async function deriveSharedSecret(privateKey, publicKey) {
  try {
    const importedPrivateKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKey,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveBits']
    );

    const importedPublicKey = await crypto.subtle.importKey(
      'spki',
      publicKey,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );

    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: importedPublicKey,
      },
      importedPrivateKey,
      256
    );

    return sharedSecret;
  } catch (error) {
    throw new Error('Error deriving shared secret: ' + error.message);
  }
}

// HKDF
let textEncoder = new TextEncoder();
let aesgcmInfo = textEncoder.encode('AESGCM');
let macInfo = textEncoder.encode('MAC');

async function deriveKeysHKDF(sharedSecret, salt) {
  try {
  const sharedSecretKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: "HKDF" },
    false,
    ['deriveKey']
  );

  const encryptionKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt: salt,
      info: aesgcmInfo,
      hash: { name: 'SHA-256' },
    },
    sharedSecretKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const macKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt: salt,
      info: macInfo,
      hash: { name: 'SHA-256' },
    },
    sharedSecretKey,
    { name: 'HMAC', hash: { name: 'SHA-256' }, length: 256 },
    false,
    ['sign', 'verify']
  );

  return { encryptionKey, macKey };
} catch (error) {
  throw new Error('Error deriving keys using HKDF: ' + error.message);
}
}

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(arrayBuffer) {
  const uint8Array = new Uint8Array(arrayBuffer);
  let binaryString = '';
  for (let i = 0; i < uint8Array.length; i++) {
    binaryString += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binaryString);
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const length = binaryString.length;
  const uint8Array = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    uint8Array[i] = binaryString.charCodeAt(i);
  }
  return uint8Array.buffer;
}

async function keyGeneration(username) {
  const KeyPair = await generateKeyPair();
  const exportedPublicKey = await window.crypto.subtle.exportKey('spki', KeyPair.publicKey);
  const StringPublicKey = arrayBufferToBase64(exportedPublicKey);

  // Set the ECDH public key in the hidden input field
  document.getElementById("ecdhPublicKey").value = StringPublicKey;
  // Export the ECDH private key
  const exportedPrivateKey = await window.crypto.subtle.exportKey('pkcs8', KeyPair.privateKey);
  const StringPrivateKey = arrayBufferToBase64(exportedPrivateKey);
  localStorage.setItem(`ecdhPrivateKey_${username}`, StringPrivateKey);
  console.log("Private key:", KeyPair.privateKey);
  console.log("PublicKey key:", KeyPair.publicKey);
  console.log("PublicKey key in Base64:"+ document.getElementById("ecdhPublicKey").value);
  console.log("Private key in Base64:"+ localStorage.getItem(`ecdhPrivateKey_${username}`));
}

// Function to convert a number to Uint8Array
function numberToUint8Array(number) {
  const buffer = new ArrayBuffer(12);
  const view = new DataView(buffer);

  for (let i = 0; i < 12; i++) {
    const byte = number & 0xFF; // Extract the least significant byte
    view.setUint8(i, byte); // Set the byte in the buffer
    number >>= 8; // Shift the number by 8 bits to the right
  }

  return new Uint8Array(buffer);
}



