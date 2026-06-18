# Guion de presentación

**Proyecto:** Autenticación contraseña + TOTP con auto-evaluación adversarial
**Expositores:** Miguel Ulloa Wood (M) · Alexander Burgos Quezada (A)
**Duración objetivo:** ~14 min + 5 min de preguntas
**Convención:** *(A)* / *(M)* indica quién habla. Los tiempos son acumulativos aproximados.

> Consejo: las diapositivas tienen poco texto a propósito. Este guion es lo que se dice;
> las láminas solo apoyan. Practicar para no leer.

---

## Slide 1 — Portada · *(A)* · 0:00–0:30

"Buenos días. Somos Alexander y Miguel. Presentamos un sistema de autenticación de dos
factores —contraseña más TOTP— pero con un giro: no solo lo construimos, también lo
**atacamos a nosotros mismos** para medir si sus defensas funcionan. Ese proceso
adversarial es el centro de la charla."

## Slide 2 — El problema · *(A)* · 0:30–1:15

"Las contraseñas solas son un factor débil: se reutilizan y se filtran en brechas. El
segundo factor las complementa: aunque roben la contraseña, falta el código. TOTP es el
2FA más usado porque solo necesita un secreto compartido y un reloj. Pero implementarlo
**bien** es sutil: comparar mal, no limitar intentos o guardar mal el secreto rompe
toda la garantía. Ese es nuestro tema."

## Slide 3 — Qué construimos · *(A)* · 1:15–2:15

"Construimos un servidor Flask local con login en dos pasos. El núcleo TOTP está hecho
**desde cero** con la librería estándar, para controlar cada paso. Tiene enrolamiento
por QR, códigos de respaldo y un panel. Implementamos defensas concretas —que veremos— y,
lo más distintivo, un **arnés que ataca y mide** nuestras propias defensas. A la derecha,
la pantalla de login real."

## Slide 4 — Conexión con el curso · *(A)* · 2:15–3:00

"El proyecto toca casi todo el curso: criptografía aplicada, autenticación, modelo de
amenaza, un canal lateral por tiempo, defensa en profundidad y seguridad web. No es solo
cripto." *(Transición: "Miguel sigue con el diseño.")*

## Slide 5 — Modelo de amenaza · *(M)* · 3:00–4:00

"Definimos explícitamente al atacante: remoto, sin credenciales, que puede adivinar,
medir tiempos de respuesta, reenviar peticiones y —caso interesante— obtener una copia
del archivo de base de datos. A la izquierda, lo que mitigamos; a la derecha, el riesgo
residual que dejamos **fuera de alcance** a propósito y discutiremos al final."

## Slide 6 — Arquitectura · *(M)* · 4:00–4:45

"El servidor coordina módulos con responsabilidades acotadas —privilegio mínimo y
separación—: TOTP, criptografía, limitador de intentos y sesiones. La base de datos
guarda hashes de contraseña, el secreto **cifrado**, y metadatos anti-replay y lockout."

## Slide 7 — Cómo funciona TOTP · *(M)* · 4:45–6:00

"TOTP es HOTP aplicado al tiempo. Tomamos el número de paso de 30 segundos, calculamos
HMAC-SHA1 del secreto con ese número, aplicamos la **truncación dinámica** del RFC 4226
y tomamos módulo un millón para 6 dígitos. Como el teléfono y el servidor comparten
secreto y reloj, generan el mismo código sin comunicarse."

## Slide 8 — Login en dos pasos · *(M)* · 6:00–7:00

"El estado intermedio vive en el **servidor**: tras validar la contraseña la sesión
queda 'pendiente de 2FA'; solo al validar el código se promueve a autenticada y se
**regenera** la sesión, evitando fijación. La verificación del código incluye ventana de
tolerancia, anti-replay y comparación en tiempo constante." *(Transición: "Alexander
detalla las decisiones de seguridad.")*

## Slide 9 — Decisiones de seguridad · *(A)* · 7:00–8:00

"Esta tabla es el corazón técnico: cada amenaza con su defensa. Fuga de la base de datos:
bcrypt y secreto cifrado. Fuerza bruta: lockout. Tiempo: compare_digest. Replay: último
paso consumido. Más enumeración, CSRF, SQLi y fijación de sesión. De las cuatro más
interesantes mostramos **evidencia medida**."

## Slide 10 — El error de la propuesta · *(A)* · 8:00–9:15

"Nuestro mayor aprendizaje. La propuesta decía 'secretos hasheados con bcrypt'. Al
implementarlo nos dimos cuenta: un secreto TOTP **no se puede hashear**, porque para
verificar hay que **recalcular** el HMAC, y un hash es de una sola vía. La contraseña sí
se hashea; el secreto hay que **cifrarlo** de forma reversible. Lo ciframos con Fernet
—AES más HMAC— y la clave maestra vive fuera de la base de datos. Distinguir hashing de
cifrado **según el caso de uso** fue la lección clave."

## Slide 11 — Demo · *(A)* · 9:15–10:00

"En la demo: el usuario escanea el QR, su app genera códigos, ingresa el de 6 dígitos y
entra. Aquí están las capturas reales del flujo." *(Si hay tiempo y proyector: mostrar en
vivo `make run` en localhost:5000.)* *(Transición: "Miguel muestra los resultados.")*

## Slide 12 — E1 Conformidad RFC · *(M)* · 10:00–10:45

"Validamos contra los vectores de prueba oficiales de los RFC: 16 de 16 correctos. Esto
prueba que el algoritmo es correcto y, por construcción, **interoperable** con cualquier
app estándar. Además lo enrolamos en Google Authenticator y aceptó."

## Slide 13 — E3 Timing · *(M)* · 10:45–11:45

"Medimos el tiempo de comparación según cuántos caracteres iniciales aciertan. La
comparación ingenua **sube** linealmente: esa pendiente es la fuga que permitiría
adivinar carácter por carácter. compare_digest es **plana**. Honestidad metodológica:
amplificamos con un token de 32 caracteres para que se vea; en 6 dígitos la fuga es
pequeña, pero como compare_digest no cuesta nada, no hay excusa para no usarlo."

## Slide 14 — E4 Fuerza bruta · *(M)* · 11:45–12:45

"Un código tiene un millón de valores, pero lo decisivo es **cuántos intentos por hora**
permitimos. Sin protección: 180 mil por hora, comprometido en horas. Con lockout: 12 por
hora; el tiempo esperado de un ataque exitoso pasa a más de **800 días**. Cuatro órdenes
de magnitud por una defensa simple."

## Slide 15 — E5 + E6 · *(M)* · 12:45–13:30

"El replay: un código vale **una vez**; reusarlo en su ventana se rechaza. Y las 33
pruebas automatizadas pasan, desde los vectores RFC hasta CSRF." *(Transición:
"Alexander cierra con límites y aprendizajes.")*

## Slide 16 — Limitaciones · *(A)* · 13:30–14:15

"Somos honestos sobre los límites. TOTP es **phishable**: un sitio falso en tiempo real
reusa el código al instante; la defensa real es WebAuthn. La seguridad del secreto
depende de proteger la clave maestra. En la demo no hay HTTPS y el throttle es en
memoria. Y nada protege un dispositivo con malware."

## Slide 17 — Aprendizajes · *(A)* · 14:15–14:45

"El gran aprendizaje: lo difícil no es el happy path, son los detalles que deciden si
resiste un ataque. Hashing no es cifrado. Y **medir** una defensa cambia la confianza
frente a solo suponer que funciona. Como futuro: WebAuthn, throttle distribuido y KMS."

## Slide 18 — Cierre / Q&A · *(A+M)* · 14:45+

"Gracias. Todo es reproducible con `make all`. Quedamos atentos a sus preguntas."

---

# Banco de preguntas y respuestas (para los 5 min)

**1. ¿No está roto SHA-1? ¿Por qué usarlo?**
Las colisiones de SHA-1 afectan a *firmas*, no a **HMAC-SHA1**, que sigue siendo seguro.
Las apps autenticadoras usan SHA-1 por compatibilidad y el RFC 6238 lo especifica.
Igualmente nuestro código soporta SHA-256/512 cambiando un parámetro.

**2. ¿Por qué cifrar el secreto y no usar un HSM?**
En producción correspondería un KMS/HSM. Aquí demostramos el **principio**: la clave
maestra vive fuera de la base de datos, de modo que filtrar solo el `.db` no revela los
secretos. Lo declaramos como riesgo residual.

**3. El timing attack, ¿es explotable sobre una red real?**
Difícilmente: el ruido de red oculta nanosegundos. Por eso lo amplificamos en el
experimento. El punto es de **principio**: la fuga existe y `compare_digest` la elimina
sin costo, así que no hay razón para usar `==`.

**4. ¿El lockout no permite un DoS contra una cuenta?**
Sí, es un trade-off real: un atacante podría bloquear a una víctima a propósito.
Mitigaciones: combinar con throttle por IP (lo hacemos), usar *backoff* en vez de bloqueo
duro, CAPTCHA y notificar al usuario. Es una decisión de diseño consciente.

**5. La ventana ±1, ¿no agranda la superficie?**
Correcto: cada paso extra triplica los códigos válidos simultáneos. Elegimos ±1 como
balance usabilidad/seguridad y es configurable; con 0 sería más estricto pero frágil al
desfase de reloj.

**6. ¿Por qué generan el QR en el servidor y no con qrcode.js como decía la propuesta?**
Para no depender de JavaScript de terceros y poder aplicar una CSP estricta. El secreto
llega igual al cliente; el cambio es de simplicidad y reduce superficie en el navegador.

**7. ¿Códigos de respaldo con SHA-256 no es débil?**
No: son de **alta entropía** (~49 bits), así que no hay diccionario factible. bcrypt
(lento) solo es necesario para secretos de **baja** entropía como contraseñas; para alta
entropía, un hash rápido es adecuado.

**8. ¿Cómo evitan replay si el reloj varía?**
Guardamos por usuario el **último paso consumido** y solo aceptamos códigos de pasos
estrictamente mayores. Es monotónico y no depende de que el reloj sea perfecto.

**9. ¿Diferencia entre HOTP y TOTP?**
HOTP usa un **contador**; TOTP usa el **tiempo** como contador. TOTP evita tener que
sincronizar un contador entre cliente y servidor.

**10. ¿Esto protege contra phishing?**
TOTP **no** frente a un MITM en tiempo real. La defensa que sí lo logra es
**WebAuthn/passkeys**, porque la credencial está ligada al origen del sitio. Es nuestro
trabajo futuro principal.

**11. ¿Probaron interoperabilidad con una app real?**
Sí. Pasamos los vectores oficiales (interoperabilidad por construcción) y, además,
enrolamos el secreto en Google/Microsoft Authenticator y el servidor aceptó sus códigos.

**12. ¿Por qué Flask y no un framework "más seguro"?**
Es una demo educativa; el foco es la **lógica de seguridad**, no el framework. Las mismas
decisiones (cifrado, compare_digest, lockout, CSRF) aplican en cualquier stack.
