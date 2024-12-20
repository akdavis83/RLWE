// RLWE-based Key Exchange in JavaScript

// Constants
const n = 1024; // Ring dimension
const q = 40961; // Prime modulus
const W = [...Array(1024).keys()].map((i) => (i + 1) % q); // Precomputed twiddle factors
const W_rev = [...Array(1024).keys()].map((i) => (q - i - 1) % q); // Reverse twiddle factors

// Modular arithmetic helpers
function mod(x, m) {
  return ((x % m) + m) % m;
}

function mulMod(a, b, m) {
  return mod(a * b, m);
}

function addMod(a, b, m) {
  return mod(a + b, m);
}

function subMod(a, b, m) {
  return mod(a - b, m);
}

// FFT functions
function fftForward(x) {
  let step = 1;
  for (let m = n >> 1; m >= 1; m >>= 1) {
    let index = 0;
    for (let j = 0; j < m; j++) {
      for (let i = j; i < n; i += m << 1) {
        const t0 = addMod(x[i], x[i + m], q);
        const t1 = mulMod(subMod(x[i], x[i + m], q), W[index], q);
        x[i] = t0;
        x[i + m] = t1;
      }
      index = mod(index + (n - step), n);
    }
    step <<= 1;
  }
}

function fftBackward(x) {
  let step = n >> 1;
  for (let m = 1; m < n; m <<= 1) {
    let index = 0;
    for (let j = 0; j < m; j++) {
      for (let i = j; i < n; i += m << 1) {
        const t0 = x[i];
        const t1 = mulMod(x[i + m], W_rev[index], q);
        x[i] = addMod(t0, t1, q);
        x[i + m] = subMod(t0, t1, q);
      }
      index = mod(index + (n - step), n);
    }
    step >>= 1;
  }
}

// Key exchange functions
function generateKeyPair() {
  const privateKey = Array.from({ length: n }, () => Math.floor(Math.random() * q));
  const publicKey = privateKey.slice(); // Copy private key
  fftForward(publicKey); // Transform to frequency domain
  return { privateKey, publicKey };
}

function encapsulate(publicKey) {
  const randomPoly = Array.from({ length: n }, () => Math.floor(Math.random() * q));
  const ciphertext = randomPoly.slice(); // Copy randomPoly
  fftForward(ciphertext); // Transform to frequency domain
  const sharedSecret = randomPoly.map((val, i) => mulMod(val, publicKey[i], q));
  return { ciphertext, sharedSecret };
}

function decapsulate(ciphertext, privateKey) {
  const sharedSecret = ciphertext.map((val, i) => mulMod(val, privateKey[i], q));
  fftBackward(sharedSecret); // Transform back to time domain
  return sharedSecret;
}

// Example usage
const { privateKey, publicKey } = generateKeyPair();
console.log("Private Key:", privateKey);
console.log("Public Key:", publicKey);

const { ciphertext, sharedSecret: senderSharedSecret } = encapsulate(publicKey);
console.log("Ciphertext:", ciphertext);
console.log("Sender's Shared Secret:", senderSharedSecret);

const receiverSharedSecret = decapsulate(ciphertext, privateKey);
console.log("Receiver's Shared Secret:", receiverSharedSecret);

// Verify shared secret match
console.log(
  "Shared secrets match:",
  JSON.stringify(senderSharedSecret) === JSON.stringify(receiverSharedSecret)
);
