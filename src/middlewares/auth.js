// Middlewares de autenticación (sesión o JWT).
import { verifyAccessToken } from "../services/jwt.service.js";

/** Exige sesión activa (cookie de sesión) */
export function requireSession(req, res, next) {
  // req.session?.user: chequeamos si en el objeto req.session existe la propiedad user | ?. es optional chaining: significa “si session existe y además tiene user”
  if (req.session?.user) return next();
  return res.status(401).json({ error: "Unauthorized (session)" });
}

/** Exige Authorization: Bearer <token> válido */
export function requireJWT(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const [type, token] = header.split(" ");
    if (type !== "Bearer" || !token) {
      return res.status(401).json({ error: "Missing Bearer token" });
    }
    const claims = verifyAccessToken(token);
    // Guardamos “usuario” derivado del token para la ruta
    req.user = { id: claims.sub, email: claims.email, roles: claims.roles || [] };
    req.jti = claims.jti;
    return next();
    // catch: se usa para atrapar errores que ocurren dentro de un bloque try
  } catch {
    return res.status(401).json({ error: "Unauthorized (jwt)" });
  }
}

/** RBAC Role-Based Access Control simple: exige que el usuario tenga al menos uno de los roles pedidos */
// los tres puntos se usan como operador rest, Significa: “mete todos los argumentos que me pasen en un array llamado roles”
// La función requireRoles puede recibir 1, 2, 3 o más argumentos, y todos se guardan en un array llamado roles
export function requireRoles(...roles) {
  return (req, res, next) => {
    const sessionRoles = req.session?.user?.roles || [];
    const jwtRoles = req.user?.roles || [];
    // Los tres puntos aquí son spread → “expande el array”, junta ambos arrays en uno solo | effective: conjunto de todos los roles únicos del usuario, sin importar si vinieron de sesión o de JWT
    const effective = new Set([...sessionRoles, ...jwtRoles]);
    const ok = roles.some(r => effective.has(r)); //Revisa si el usuario tiene al menos uno de los roles que pasaste
    if (!ok) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}
