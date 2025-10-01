// Firma/verifica tokens de acceso (cortos) con HS256.
import jwt from "jsonwebtoken";
import { env } from "../config/env.js";
import { nanoid } from "nanoid"; // generar identificadores únicos (IDs) de forma rápida y segura

// Lista (set) de JTI (JWT ID) revocados para logout con JWT (MVP: memoria)
const revokedJtis = new Set();

/** Emite un access token con jti único (para revocación) */
export function signAccessToken(payload) {
  // jti: ID único del token
  const jti = nanoid();
  const token = jwt.sign({ ...payload, jti }, env.jwt.accessSecret, {
    expiresIn: env.jwt.accessExpires
  });
  return { token, jti };
}

/** Verifica token, caducidad y que jti no esté revocado */
export function verifyAccessToken(token) {
  const claims = jwt.verify(token, env.jwt.accessSecret); // lanza error si está mal
  if (revokedJtis.has(claims.jti)) {
    const err = new Error("Token revoked");
    err.name = "UnauthorizedError";
    throw err;
  }
  return claims;
}

/** Revoca un jti (se usa en logout JWT) */
export function revokeJti(jti) {
  if (jti) revokedJtis.add(jti);
}
