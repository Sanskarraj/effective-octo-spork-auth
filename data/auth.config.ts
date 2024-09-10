import Credentials from "next-auth/providers/credentials";
import type { NextAuthConfig } from "next-auth";
import bcryptjs from "bcryptjs";
import { LoginSchema } from "./schemas";
import { getUserByEmail } from "./data/user";
import Github from "next-auth/providers/github";
import Google from "next-auth/providers/google";

//generates 6 code
import { customAlphabet } from 'nanoid';
const generateUniqueCode = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 6);



import path from 'path';
import { promises as fs } from 'fs';
import { break256, enhancedAESEncrypt, rxreverse, the256 } from "./lib/tor";
import { getCountryFromLocale } from "./lib/map";

interface Chacha20Module {
  default: (module_or_path: WebAssembly.Module | string, maybe_memory?: WebAssembly.Memory) => Promise<InitOutput>;
  chacha20_encrypt: (key: Uint8Array, data: Uint8Array) => Uint8Array;
  chacha20_decrypt: (key: Uint8Array, data: Uint8Array) => Uint8Array;
}

interface InitOutput {
  memory: WebAssembly.Memory;
}

const chacha20ModulePromise: Promise<Chacha20Module> = import('chacha20');

async function loadWasmModule() {
  try {
    const wasmPath = path.join(process.cwd(), 'pkg-cha-dec', 'chacha20_bg.wasm');
    const wasmBuffer = await fs.readFile(wasmPath);
    const chacha20Module = await chacha20ModulePromise;
    await chacha20Module.default(wasmBuffer);
    return chacha20Module;
  } catch (error) {
    console.error("Error loading WebAssembly module:", error);
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      throw new Error("WebAssembly file not found. Please ensure 'chacha20_bg.wasm' is in the 'pkg-cha-dec' directory.");
    }
    throw new Error("Failed to initialize encryption module");
  }
}

let initializedModule: Chacha20Module | null = null;

async function getOrInitializeModule() {
  if (!initializedModule) {
    initializedModule = await loadWasmModule();
  }
  return initializedModule;
}

export default {
  providers: [
    Github({
      clientId: process.env.GITHUB_ID_CLIENT,
      clientSecret: process.env.GITHUB_SECRET_CLIENT,
      async profile(profile) {

        console.log("profile",profile)
        const key = the256(profile.email);
        console.log("key::", key);
        const chacha20Module = await getOrInitializeModule();
        const k2 = break256(key);
        console.log("key2", k2);
        console.log("key2", k2);
        console.log("key2", k2);
        console.log("key2", k2);

        const safeKey = rxreverse(enhancedAESEncrypt(k2, 7, 5));
        console.log("safe key::", safeKey);
        console.log("safe key::", safeKey);
        console.log("safe key::", safeKey);
        console.log("safe key::", safeKey);

        const keyBytes = new TextEncoder().encode(safeKey.padEnd(32));
//         console.log ("profile locale",profile.locale);

//         const locale = profile.locale;

//         const country = getCountryFromLocale(locale);
// console.log ("locale",locale);
// console.log ("country",country)



        const emailBytes = new TextEncoder().encode(profile.email);
        const encryptedEmailBytes = chacha20Module.chacha20_encrypt(keyBytes, emailBytes);
        const encryptedEmail = Buffer.from(encryptedEmailBytes).toString('hex');
        console.log("encrypted email", encryptedEmail);

        console.log(encryptedEmail);

        
        
        // const countryBytes = new TextEncoder().encode(country);
        // const encryptedCountryBytes = chacha20Module.chacha20_encrypt(keyBytes, countryBytes);
        // const encryptedCountry = Buffer.from(encryptedCountryBytes).toString('hex');
    
        // console.log("encrypted country",encryptedCountry);


        const nameBytes = new TextEncoder().encode(profile.name);
        const encryptedNameBytes = chacha20Module.chacha20_encrypt(keyBytes, nameBytes);
        const encryptedName = Buffer.from(encryptedNameBytes).toString('hex');

        console.log("encrypted name",encryptedName);

const pass = generateUniqueCode();
console.log ("generated 6 code",pass)
const hashedPassword = await bcryptjs.hash(pass, 11);





        
        // const k4 = sxreverse(autoAesEncrypt(k2));
      //         console.log("AES encrypted key:", k4);


        return {
          id: profile.sub,
          name: encryptedName,
          email: encryptedEmail,
          image: null,
          acccount : profile.account,
          key:k2,
          country:null,
          password:hashedPassword,
        };
      },
    }),
    Google({
      clientId: process.env.GOOGLE_ID_CLIENT,
      clientSecret: process.env.GOOGLE_SECRET_CLIENT,

      async profile(profile) {

        console.log("profile",profile)
        const key = the256(profile.email);
        console.log("key::", key);
        const chacha20Module = await getOrInitializeModule();
        const k2 = break256(key);
        console.log("key2", k2);
        console.log("key2", k2);
        console.log("key2", k2);
        console.log("key2", k2);

        const safeKey = rxreverse(enhancedAESEncrypt(k2, 7, 5));
        console.log("safe key::", safeKey);
        console.log("safe key::", safeKey);
        console.log("safe key::", safeKey);
        console.log("safe key::", safeKey);

        const keyBytes = new TextEncoder().encode(safeKey.padEnd(32));
        console.log ("profile locale",profile.locale);

        const locale = profile.locale;

        const country = getCountryFromLocale(locale);
console.log ("locale",locale);
console.log ("country",country)



        const emailBytes = new TextEncoder().encode(profile.email);
        const encryptedEmailBytes = chacha20Module.chacha20_encrypt(keyBytes, emailBytes);
        const encryptedEmail = Buffer.from(encryptedEmailBytes).toString('hex');
        console.log("encrypted email", encryptedEmail);

        console.log(encryptedEmail);

        
        
        // const countryBytes = new TextEncoder().encode(country);
        // const encryptedCountryBytes = chacha20Module.chacha20_encrypt(keyBytes, countryBytes);
        // const encryptedCountry = Buffer.from(encryptedCountryBytes).toString('hex');
    
        // console.log("encrypted country",encryptedCountry);


        const nameBytes = new TextEncoder().encode(profile.name);
        const encryptedNameBytes = chacha20Module.chacha20_encrypt(keyBytes, nameBytes);
        const encryptedName = Buffer.from(encryptedNameBytes).toString('hex');

        console.log("encrypted name",encryptedName);


        const pass = generateUniqueCode();
console.log ("generated 6 code",pass)
const hashedPassword = await bcryptjs.hash(pass, 11);



        // profile.acccount.scope = null;
        // profile.acccount.scope = "threadx_one"


        
        // const k4 = sxreverse(autoAesEncrypt(k2));
      //         console.log("AES encrypted key:", k4);


        return {
          id: profile.sub,
          name: encryptedName,
          email: encryptedEmail,
          image: null,
          acccount : profile.account,
          key:k2,
          country:null,
          password:hashedPassword
        };
      },
      
    }),
    Credentials({
      async authorize(credentials) {
        try {
          console.log("---------------------------------flow two starts--------------");

          const validatedFields = LoginSchema.safeParse(credentials);
          console.log(validatedFields);
          console.log("---------------------------------flow two --------------");

          if (validatedFields.success) {
            const { email, password } = validatedFields.data;

            const key = the256(email);
            console.log("key::", key);
            console.log("validated fields", validatedFields.data);

            const chacha20Module = await getOrInitializeModule();
            console.log("---------------------------------flow two --------------");

            const k2 = break256(key);
            const safeKey = rxreverse(enhancedAESEncrypt(k2, 7, 5));
            const keyBytes = new TextEncoder().encode(safeKey.padEnd(32));
            console.log("---------------------------------flow two --------------");

            const emailBytes = new TextEncoder().encode(email);
            const encryptedEmailBytes = chacha20Module.chacha20_encrypt(keyBytes, emailBytes);
            const encryptedEmail = Buffer.from(encryptedEmailBytes).toString('hex');
            console.log("encrypted email", encryptedEmail);

            console.log("---------------------------------flow two --------------");

            console.log(encryptedEmail);
            console.log(password);

            const user = await getUserByEmail(encryptedEmail);

            console.log("---------------------------------flow two --------------");

            if (!user || !user.password) return null;
            user.email = email;
            console.log(user);
            console.log(user.email);
            
            user.country = Buffer.from(chacha20Module.chacha20_decrypt(keyBytes, Buffer.from(user.country, 'hex'))).toString();
            console.log(user);
            console.log(user.country);
            const passwordMatch = await bcryptjs.compare(password, user.password);

            console.log("---------------------------------flow two --------------");
            console.log(user);

            if (passwordMatch) return user;
          }
          return null;
        } catch (error) {
          console.error("Authorization error:", error);
          return null;
        }
      }
    })
  ],
} satisfies NextAuthConfig;
