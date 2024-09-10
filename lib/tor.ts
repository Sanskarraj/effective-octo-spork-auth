import { sha256 } from 'js-sha256';
import { chacha20_encrypt, chacha20_decrypt } from 'chacha20';

// let chacha20Initialized = false;

// export async function initializeChacha20Wasm() {
//   try {
//     if (!chacha20Initialized) {
//       await init();
//       chacha20Initialized = true;
//       console.log("ChaCha20 WASM Module Initialized");
//     }
//   } catch (error) {
//     console.error("ChaCha20 WASM Initialization error:", error);
//   }
// }

// 
export const applyAes = (str:string) => {
    return str.replace(/[a-zA-Z]/g, (char: string) => {
      // Get the char code of the character
      const charCode = char.charCodeAt(0);

      // Check if it's a lowercase letter
      if (charCode >= 97 && charCode <= 122) {
        // Apply ROT13 and handle wrap-around
        return String.fromCharCode(((charCode - 97 + 13) % 26) + 97);
      }

      // Check if it's an uppercase letter
      if (charCode >= 65 && charCode <= 90) {
        // Apply ROT13 and handle wrap-around
        return String.fromCharCode(((charCode - 65 + 13) % 26) + 65);
      }

      // If it's not a letter, return the character unchanged
      return char;
    })}


      // Encrypt function
export const autoAesEncrypt = (str: string) => {
    let extendedKey = "mNPbI4nrt14xEdyYnGhhYQ5fRM" + str; // Extend the key by appending the plaintext
    let keyIndex = 0;
  
    return str.replace(/[a-zA-Z0-9]/g, (char: string) => {
      const charCode = char.charCodeAt(0);
      const shift = extendedKey.charCodeAt(keyIndex % extendedKey.length) % 26;
      keyIndex++;
  
      // Handle lowercase letters
      if (charCode >= 97 && charCode <= 122) {
        return String.fromCharCode(((charCode - 97 + shift) % 26) + 97);
      }
  
      // Handle uppercase letters
      if (charCode >= 65 && charCode <= 90) {
        return String.fromCharCode(((charCode - 65 + shift) % 26) + 65);
      }
  
      // Handle numbers (0-9)
      if (charCode >= 48 && charCode <= 57) {
        return String.fromCharCode(((charCode - 48 + (shift % 10)) % 10) + 48);
      }
  
      // If it's not a letter or number, return the character unchanged
      return char;
    });
  };
  
  // Decrypt function
  export const autoAesDecrypt = (str: string) => {
    let extendedKey = "mNPbI4nrt14xEdyYnGhhYQ5fRM" + str; // Extend the key by appending the plaintext
    let keyIndex = 0;
  
    return str.replace(/[a-zA-Z0-9]/g, (char: string) => {
      const charCode = char.charCodeAt(0);
      const shift = extendedKey.charCodeAt(keyIndex % extendedKey.length) % 26;
      keyIndex++;
  
      // Handle lowercase letters
      if (charCode >= 97 && charCode <= 122) {
        return String.fromCharCode(((charCode - 97 - shift + 26) % 26) + 97);
      }
  
      // Handle uppercase letters
      if (charCode >= 65 && charCode <= 90) {
        return String.fromCharCode(((charCode - 65 - shift + 26) % 26) + 65);
      }
  
      // Handle numbers (0-9)
      if (charCode >= 48 && charCode <= 57) {
        return String.fromCharCode(((charCode - 48 - (shift % 10) + 10) % 10) + 48);
      }
  
      // If it's not a letter or number, return the character unchanged
      return char;
    });
  };
  


  // Function to compute modular inverse
const modInverse = (a: number, m: number): number => {
    let m0 = m, x0 = 0, x1 = 1;
    if (m === 1) return 0;
  
    while (a > 1) {
      let q = Math.floor(a / m);
      let t = m;
      m = a % m;
      a = t;
      t = x0;
      x0 = x1 - q * x0;
      x1 = t;
    }
  
    if (x1 < 0) x1 += m0;
  
    return x1;
  };
  
  // Helper function to compute GCD
  const gcd = (x: number, y: number): number => y === 0 ? x : gcd(y, x % y);
  
  // Optimized Enhanced Affine Cipher Encryption
  export const enhancedAESEncrypt = (str: string, a: number, b: number) => {
    if (gcd(a, 26) !== 1) {
      throw new Error("a must be coprime with 26 for the cipher to work.");
    }
  
    // Precompute the shift array
    const shiftArray = Array.from({ length: str.length }, (_, index) => (index % 26) + b);
  
    return str.split('').map((char, index) => {
      const charCode = char.charCodeAt(0);
      const shift = shiftArray[index];
  
      if (charCode >= 97 && charCode <= 122) { // Lowercase letters
        return String.fromCharCode(((a * (charCode - 97) + shift) % 26 + 26) % 26 + 97);
      }
      if (charCode >= 65 && charCode <= 90) { // Uppercase letters
        return String.fromCharCode(((a * (charCode - 65) + shift) % 26 + 26) % 26 + 65);
      }
      if (charCode >= 48 && charCode <= 57) { // Digits (0-9)
        return String.fromCharCode(((a * (charCode - 48) + shift) % 10 + 10) % 10 + 48);
      }
      return char; // Non-alphanumeric characters
    }).join('');
  };
  
  // Optimized Enhanced Affine Cipher Decryption
  export const enhancedAESDecrypt = (str: string, a: number, b: number) => {
    if (gcd(a, 26) !== 1) {
      throw new Error("a must be coprime with 26 for the cipher to work.");
    }
  
    const aInv = modInverse(a, 26);
  
    // Precompute the shift array
    const shiftArray = Array.from({ length: str.length }, (_, index) => (index % 26) + b);
  
    return str.split('').map((char, index) => {
      const charCode = char.charCodeAt(0);
      const shift = shiftArray[index];
  
      if (charCode >= 97 && charCode <= 122) { // Lowercase letters
        return String.fromCharCode(((aInv * (charCode - 97 - shift + 26)) % 26 + 26) % 26 + 97);
      }
      if (charCode >= 65 && charCode <= 90) { // Uppercase letters
        return String.fromCharCode(((aInv * (charCode - 65 - shift + 26)) % 26 + 26) % 26 + 65);
      }
      if (charCode >= 48 && charCode <= 57) { // Digits (0-9)
        return String.fromCharCode(((aInv * (charCode - 48 - shift + 10)) % 10 + 10) % 10 + 48);
      }
      return char; // Non-alphanumeric characters
    }).join('');
  };


  export const the256 = (s: string): string => {
    const hexHash = sha256(s);
    return hexHash;
  };
  

  export const break256 = (s: string): string => {
    if (s.length === 0) return '';
  
    const midpoint = Math.floor(s.length / 2);
  
    return s.slice(0, midpoint);
  };


export const rxreverse= (s: string): string => {
    return s.split('').reverse().join('')
}


export const adv40Encrypt =  (s: string, k: string): string => {
  try {
    // await initializeChacha20Wasm();
    const keyBytes = new TextEncoder().encode(k.padEnd(32)); // Ensure key is 32 bytes
    const messageBytes = new TextEncoder().encode(s);
    const encrypted = chacha20_encrypt(keyBytes, messageBytes);
    return Buffer.from(encrypted).toString('hex');
  } catch (error) {
    console.error("Encryption error:", error);
    return error.toString();
  }
};

export const adv40Decrypt =  (s: string, k: string): string => {
  try {
    // await initializeChacha20Wasm();
    const encryptedBytes = new Uint8Array(Buffer.from(s, 'hex'));
    const keyBytes = new TextEncoder().encode(k.padEnd(32)); // Ensure key is 32 bytes
    const decrypted = chacha20_decrypt(keyBytes, encryptedBytes);
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("Decryption error:", error);
    return error.toString();
  }
};



export const sxreverse = (s: string): string => {
  const q = break512(s); // Split the string into two parts
  return rxreverse(q.c1) + rxreverse(q.c2); // Reverse each part and concatenate
};


  export const break512 = (s: string): { c1: string, c2: string } => {
    if (s.length === 0) return { c1: '', c2: '' };
  
    const midpoint = Math.floor(s.length / 2);
  
    return {
      c1: s.slice(0, midpoint),
      c2: s.slice(midpoint)
    };
  };
  









// Initialize Salsa20 WASM module
// export async function initializeSalsa20Wasm() {
//   try {
//     await initSalsa20();
//     console.log("Salsa20 WASM Module Initialized");
//   } catch (error) {
//     console.error("Salsa20 WASM Initialization error:", error);
//   }
// }







// export const adv20Encrypt = async (s: string, k1: string, k2: string): string => {
//   try {
//     await initializeSalsa20Wasm(); // Initialize Salsa20 WASM module

//     // Prepare keys and message
//     const key1Bytes = new TextEncoder().encode(k1.padEnd(16, '\0').slice(0, 16));
//     const key2Bytes = new TextEncoder().encode(k2.padEnd(16, '\0').slice(0, 16));
//     const messageBytes = new TextEncoder().encode(s);

//     // Create Salsa20 instance and encrypt message
//     const salsa20 = new Salsa20(key1Bytes, key2Bytes);
//     const encryptedBytes = salsa20.encrypt(messageBytes);

//     // Convert encrypted bytes to Base64 string
//     const base64String = btoa(String.fromCharCode.apply(null,encryptedBytes));
//     return base64String;

//   } catch (error) {
//     console.error("Encryption error:", error);
//     return error.toString(); // Optionally rethrow the error after logging it
//   }
// };



// export const adv20Decrypt = async(s: string, k1: string, k2: string ): string => {
//   try {
//     await initializeSalsa20Wasm();
//     const key1Bytes = new TextEncoder().encode(k1.padEnd(16, '\0').slice(0, 16));
//     const key2Bytes = new TextEncoder().encode(k2.padEnd(16, '\0').slice(0, 16));
//     const encryptedBytes = new Uint8Array(atob(s).split('').map(c => c.charCodeAt(0)));

//     const salsa20 = new Salsa20(key1Bytes, key2Bytes);
//     const decryptedBytes = salsa20.decrypt(encryptedBytes);
//     return (new TextDecoder().decode(decryptedBytes));
//   } catch (error) {
//     console.error("Encryption error:", error);
//     return error.toString(); // Optionally rethrow the error after logging it
//   }
// }





// export const c12 = (s: string): { c1: string, c2: string } => {
//     s = autoAesEncrypt(s);
  
//     const midpoint = Math.floor(s.length / 2);
  
//     const firstHalf = s.slice(0, midpoint);
//     const secondHalf = s.slice(midpoint);
  
//     return {
//       c1: firstHalf.split('').reverse().join(''),
//       c2: secondHalf
//     };
//   };




