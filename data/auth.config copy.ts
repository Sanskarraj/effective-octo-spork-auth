import Credentials from "next-auth/providers/credentials";
import type { NextAuthConfig } from "next-auth";
import bcryptjs from "bcryptjs";
import { LoginSchema } from "./schemas";
import { getUserByEmail, createUser } from "./data/user";
import Github from "next-auth/providers/github";
import Google from "next-auth/providers/google";

import path from 'path';
import { promises as fs } from 'fs';
import { break256, enhancedAESEncrypt, rxreverse, the256 } from "./lib/tor";

// ... (keep the existing interfaces and module loading logic)

async function encryptEmail(email: string): Promise<string> {
  const chacha20Module = await getOrInitializeModule();
  const key = the256(email);
  const k2 = break256(key);
  const safeKey = rxreverse(enhancedAESEncrypt(k2, 7, 5));
  const keyBytes = new TextEncoder().encode(safeKey.padEnd(32));
  const emailBytes = new TextEncoder().encode(email);
  const encryptedEmailBytes = chacha20Module.chacha20_encrypt(keyBytes, emailBytes);
  return Buffer.from(encryptedEmailBytes).toString('hex');
}

export default {
  providers: [
    Github({
      clientId: process.env.GITHUB_ID_CLIENT,
      clientSecret: process.env.GITHUB_SECRET_CLIENT,
    }),
    Google({
      clientId: process.env.GOOGLE_ID_CLIENT,
      clientSecret: process.env.GOOGLE_SECRET_CLIENT,
      async profile(profile) {
        const encryptedEmail = await encryptEmail(profile.email);
        return {
          id: profile.sub,
          name: profile.name,
          email: profile.email,
          image: profile.picture,
          encryptedEmail: encryptedEmail,
        };
      },
    }),
    Credentials({
      // ... (keep the existing Credentials provider configuration)
    })
  ],
  callbacks: {
    async signIn({ user, account }) {
      if (account?.provider === 'google') {
        const encryptedEmail = (user as any).encryptedEmail;
        const existingUser = await getUserByEmail(encryptedEmail);
        
        if (!existingUser) {
          // Create a new user with the encrypted email
          await createUser({
            name: user.name!,
            email: encryptedEmail, // Store the encrypted email
            image: user.image,
            // Add any other fields you want to store
          });
        }
      }
      return true;
    },
    async session({ session, user }) {
      if (session.user) {
        session.user.id = user.id;
        // You can add more custom fields here if needed
      }
      return session;
    },
  },
} satisfies NextAuthConfig;