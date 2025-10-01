// CSRF “double submit cookie”: el servidor entrega un token en cookie
// y el cliente debe mandarlo también en un header. Ambos deben coincidir.
import { env } from "../config/env.js";
import { nanoid } from "nanoid";

/** Emite cookie con CSRF y devuelve el token para el front */
export function issueCsrfToken(req, res) {
  const csrfToken = nanoid(); // random
  // Cookie legible por el front (NO httpOnly) para poder leer y reenviar
  res.cookie(env.csrf.cookieName, csrfToken, {
    httpOnly: false,                 // el front puede leerla
    sameSite: "Strict",              // más estricto
    secure: false,                   // true en prod con HTTPS
    maxAge: 60 * 60 * 1000           // 1 hora
  });
  return csrfToken;
}

/** Middleware: exige cookie y header iguales */
export function requireCsrf(req, res, next) {
  const cookieToken = req.cookies[env.csrf.cookieName];
  const headerToken = req.get(env.csrf.headerName);
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: "CSRF token invalid/missing" });
  }
  return next();
}
