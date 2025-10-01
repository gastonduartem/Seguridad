// Middlewares de seguridad base (Helmet) + CORS.
import helmet from "helmet"; // configurar cabeceras HTTP (HTTP headers) que protegen tu app de ataques comunes
import cors from "cors"; // define qué dominios pueden hacer peticiones a tu API

export function securityMiddlewares() {
  // Devolvemos un array para montarlos fácil en app.js
  return [
    helmet({
      // define la CSP (Content Security Policy), que controla qué recursos se pueden cargar en tu app
      contentSecurityPolicy: {
        useDefaults: true, // arranca con las reglas por defecto de Helmet
        directives: {
          "default-src": ["'none'"], // por defecto, no se permite cargar nada desde ningún origen
          "base-uri": ["'self'"], // Controla de dónde se permite usar la etiqueta <base> en HTML, 'self' = solo desde tu mismo dominio
          "img-src": ["'self'", "data:"], // imágenes solo desde el mismo dominio o embebidas como data: | <img src="data:image/png;base64,..."> → funciona, <img src="http://cdn.hacker.com/evil.png"> → bloqueado
          "script-src": ["'self'"], // los scripts solo pueden cargarse desde el mismo dominio
          "style-src": ["'self'", "'unsafe-inline'"] // Las hojas de estilo (CSS) se pueden cargar Desde tu dominio ('self') o Inline dentro del HTML ('unsafe-inline')
        }
      },
      crossOriginResourcePolicy: { policy: "same-site" } // evita que otros sitios carguen recursos de tu app de manera insegura
    }),
    cors({
      origin: true,       // refleja origin del request (para dev)
      credentials: true   // permite enviar cookies y headers de autenticación junto con la petición
    })
  ];
}
