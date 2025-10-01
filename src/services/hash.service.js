// Servicio de hashing de contraseñas con bcrypt.
import bcrypt from "bcrypt";

// Cost 12: indica cuántas veces bcrypt aplica su algoritmo internamente
const COST = 12;

/** Recibe contraseña en texto y retorna hash seguro (irreversible). */
export async function hashPassword(plain) {
  return bcrypt.hash(plain, COST);
}

/** Compara texto vs hash y retorna boolean. */
export async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}
