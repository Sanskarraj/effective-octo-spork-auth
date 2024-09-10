import NextAuth from "next-auth";
import authConfig from "./auth.config";
import { PrismaAdapter } from "@auth/prisma-adapter";

import { db } from "./lib/db";
import { getUserByEmail, getUserById } from "./data/user";

import path from 'path';
import { promises as fs } from 'fs';
import { autoAesDecrypt, autoAesEncrypt, break256, enhancedAESEncrypt, rxreverse, sxreverse, the256 } from "./lib/tor";

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
    console.log(`Loading WebAssembly module from path: ${wasmPath}`);
    const wasmBuffer = await fs.readFile(wasmPath);
    const chacha20Module = await chacha20ModulePromise;
    console.log('WebAssembly module loaded successfully.');
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
    console.log('Initializing WebAssembly module.');
    initializedModule = await loadWasmModule();
  } else {
    console.log('WebAssembly module already initialized.');
  }
  return initializedModule;
}

export const { auth, handlers: { GET, POST }, signIn, signOut } =
  NextAuth({
    pages:{
      signIn:"auth/login",
      error:"auth/error"
    },
    callbacks: {
      async session({ token, session }) {
        console.log("Session callback:", { token, session });
        if (token.sub && session.user) {
          session.user.id = token.sub;
          session.user.role = token.role as string;
          session.user.country = token.country as string;
          session.user.key = token.key as string;
          session.user.email=token.email as string;
          session.user.name=token.name as string;

        }
        console.log("Session object after modifications:", session);
        return session;
      },
      async jwt({ token }) {
        console.log("JWT callback:", { token });
        if (!token.sub) return token;

        const existingUser = await getUserById(token.sub);
        if (!existingUser) {
          console.log("User not found by ID:", token.sub);
          return token;
        }

        token.role = existingUser.role;
        token.country = existingUser.country;
        token.key = existingUser.key;

        try {
          // const key = the256(existingUser.email);
          var k2 = existingUser.key;

          if (existingUser.key){
          // var key = autoAesDecrypt(sxreverse(existingUser.key))
          // console.log("Generated key for decryption:", key);
          // k2=key
          

          // const k2 = break256(key);
          const safeKey = rxreverse(enhancedAESEncrypt(existingUser.key, 7, 5));
          console.log("Safe key after AES encryption and reversal:", safeKey);
          const keyBytes = new TextEncoder().encode(safeKey.padEnd(32));

          const chacha20Module = await getOrInitializeModule();
          // console.log("Decryption module:", chacha20Module);
          if (existingUser.country){
          token.country = Buffer.from(chacha20Module.chacha20_decrypt(keyBytes, Buffer.from(existingUser.country, 'hex'))).toString();
          console.log("Decrypted country value:", token.country);
        
        }
          
          if (existingUser.email){
            token.email = Buffer.from(chacha20Module.chacha20_decrypt(keyBytes, Buffer.from(existingUser.email, 'hex'))).toString();
            // token.email= 
          // Buffer.from(chacha20Module.chacha20_decrypt(keyBytes, Buffer.from(existingUser.email, 'hex'))).toString();}
          }
          if(existingUser.name){
            token.name=Buffer.from(chacha20Module.chacha20_decrypt(keyBytes, Buffer.from(existingUser.name, 'hex'))).toString();
            
          }

        }
          console.log("Decrypted email value:", token.email);
        } catch (error) {
          console.error("Error during JWT processing:", error);
        }

        return token;
      },
    },
    adapter: PrismaAdapter(db),
    session: { strategy: "jwt" },
    ...authConfig
  });
