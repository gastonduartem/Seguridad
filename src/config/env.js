// Lee variables de entorno con defaults seguros para dev.
import "dotenv/config";

export const env = {
  port: Number(process.env.PORT || 3000),

  // Sesión y cookies
  sessionSecret: process.env.SESSION_SECRET || "dev_session_secret",
  cookie: {
    name: process.env.COOKIE_NAME || "sid",           // nombre de la cookie de sesión
    secure: process.env.COOKIE_SECURE === "true",     // true SOLO en producción con HTTPS
    sameSite: process.env.COOKIE_SAMESITE || "Lax",   // Lax ayuda contra CSRF
    maxAgeMs: Number(process.env.COOKIE_MAX_AGE_MS || 7 * 24 * 60 * 60 * 1000) // 7 días
  },

  // JWT corto (access)
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET || "dev_access_secret",
    accessExpires: process.env.JWT_ACCESS_EXPIRES || "15m"
  },

  // CSRF (double submit)
  csrf: {
    cookieName: process.env.CSRF_COOKIE_NAME || "csrf_token",
    headerName: process.env.CSRF_HEADER_NAME || "x-csrf-token"
  }
};
