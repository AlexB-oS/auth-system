# Guion de presentación

**Proyecto:** Autenticación contraseña + TOTP con auto-evaluación adversarial
**Expositores:** Miguel Ulloa Wood (M) · Alexander Burgos Quezada (A)
**Duración objetivo:** ~14 min + 5 min de preguntas
**Convención:** *(A)* / *(M)* indica quién habla. Los tiempos son acumulativos aproximados.

> Consejo: las diapositivas tienen poco texto a propósito. Este guion es lo que se dice;
> las láminas solo apoyan. Practicar para no leer.

> **Uso de IA:** este guion y las diapositivas se redactaron con asistencia de IA
> (Claude) a partir del contenido y las decisiones de los autores; el texto final
> fue revisado y ajustado por los expositores.

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

## Slide 3 — Qué construimos · *(A)* · 1:15–2:10

"Construimos un servidor Flask local con login en dos pasos. El núcleo TOTP está hecho
**desde cero** con la librería estándar, para controlar cada paso. Tiene enrolamiento
por QR, códigos de respaldo y un panel. Implementamos defensas concretas —que veremos— y,
lo más distintivo, un **arnés que ataca y mide** nuestras propias defensas. A la derecha,
la pantalla de login real."

## Slide 4 — Conexión con el curso · *(A)* · 2:10–2:50

"El proyecto toca casi todo el curso: criptografía aplicada, autenticación, modelo de
amenaza, un canal lateral por tiempo, defensa en profundidad y seguridad web. No es solo
cripto." *(Transición: "Miguel sigue con el diseño.")*

## Slide 5 — Modelo de amenaza · *(M)* · 2:50–3:45

"Definimos explícitamente al atacante: remoto, sin credenciales, que puede adivinar,
medir tiempos de respuesta, reenviar peticiones y —caso interesante— obtener una copia
del archivo de base de datos. A la izquierda, lo que mitigamos; a la derecha, el riesgo
residual que dejamos **fuera de alcance** a propósito y discutiremos al final."

## Slide 6 — Arquitectura · *(M)* · 3:45–4:25

"El servidor coordina módulos con responsabilidades acotadas —privilegio mínimo y
separación—: TOTP, criptografía, limitador de intentos y sesiones. La clave es que
`app.py` casi no piensa: recibe el HTTP y **delega** en `auth/accounts.py`. La base de
datos guarda hashes de contraseña, el secreto **cifrado**, y metadatos anti-replay y
lockout."

## Slide 7 — Fundamentos (sección) · *(M)* · 4:25–4:35

"Ahora bajamos al corazón del proyecto en tres láminas: cómo se genera un código TOTP,
cómo lo implementamos **desde cero**, y cómo viaja una petición de login **por el
código**. La idea es que el algoritmo y el flujo no son cajas negras: se ven y se
explican línea a línea."

## Slide 8 — Cómo funciona TOTP · *(M)* · 4:35–5:35

"TOTP es HOTP aplicado al tiempo. Tomamos el número de paso de 30 segundos, calculamos
HMAC-SHA1 del secreto con ese número, aplicamos la **truncación dinámica** del RFC 4226
y tomamos módulo un millón para 6 dígitos. Como el teléfono y el servidor comparten
secreto y reloj, generan el mismo código sin comunicarse."

## Slide 9 — El núcleo en código · *(M)* · 5:35–6:50

"Y este es el algoritmo real, en `auth/totp.py`, con solo la librería estándar. `hotp`
hace el HMAC, la truncación dinámica y el módulo. Lo importante es `verify`: recorre la
ventana de ±1 paso **sin cortar al primer acierto** —así el tiempo de respuesta no
depende de cuál paso acertó—, compara con `compare_digest`, y **devuelve el número de
paso** que coincidió. Ese valor devuelto es justo lo que después alimenta el anti-replay.
Cada detalle —no cortar, `compare_digest`, devolver el contador— es una decisión de
seguridad, no un capricho de estilo."

## Slide 10 — Login en dos pasos · *(M)* · 6:50–7:40

"El estado intermedio vive en el **servidor**: tras validar la contraseña la sesión
queda 'pendiente de 2FA'; nunca confiamos en que el cliente diga 'ya pasé la contraseña'.
Solo al validar el código se promueve a autenticada y se **regenera** la sesión, evitando
fijación. La verificación del código incluye ventana de tolerancia, anti-replay y
comparación en tiempo constante —lo que acabamos de ver en `verify`."

## Slide 11 — El flujo, en el código · *(M)* · 7:40–8:45

"La misma secuencia, pero en el código, muestra dónde vive cada defensa. La petición
entra por `app.py`, que primero valida el token CSRF y delega. En el paso de contraseña,
si el usuario no existe igual ejecutamos un bcrypt señuelo y devolvemos un mensaje
genérico: **anti-enumeración**. Si la contraseña es correcta, la sesión queda pendiente.
En el segundo paso, **desciframos** el secreto con el `SecretVault`,
verificamos el TOTP, aplicamos **anti-replay**, y solo al final regeneramos la sesión:
**anti-fijación**. El registro sigue la misma lógica, con un matiz clave: el secreto se
**cifra**, no se hashea, porque para verificar hay que **recalcular** el HMAC y un hash
es de una sola vía. Distinguir hashing de cifrado según el caso de uso fue una lección
central." *(Transición: "Alexander resume las decisiones de seguridad.")*

## Slide 12 — Decisiones de seguridad · *(A)* · 8:45–9:35

"Esta tabla condensa lo que acaban de ver en el código: cada amenaza con su defensa.
Fuga de la base de datos: bcrypt para la contraseña y secreto cifrado. Fuerza bruta:
lockout más throttle por IP. Tiempo: `compare_digest`. Replay: último paso consumido.
Más enumeración, CSRF, SQLi y fijación de sesión. De las cuatro más interesantes
mostramos a continuación **evidencia medida**."

## Slide 13 — Demo · *(A)* · 9:35–10:20

"En la demo: el usuario escanea el QR, su app genera códigos, ingresa el de 6 dígitos y
entra a una sesión protegida. Aquí están las capturas reales del flujo." *(Si hay tiempo
y proyector: mostrar en vivo `make run` en localhost:5000.)* *(Transición: "Miguel
muestra los resultados medidos.")*

## Slide 14 — E1 Conformidad RFC · *(M)* · 10:20–10:55

"Validamos contra los vectores de prueba oficiales de los RFC: 16 de 16 correctos. Esto
prueba que el algoritmo es correcto y, por construcción, **interoperable** con cualquier
app estándar. Además lo enrolamos en Google Authenticator y aceptó."

## Slide 15 — E3 Timing · *(M)* · 10:55–11:45

"Medimos el tiempo de comparación según cuántos caracteres iniciales aciertan. La
comparación ingenua **sube** linealmente: esa pendiente es la fuga que permitiría
adivinar carácter por carácter. `compare_digest` es **plana**. Honestidad metodológica:
amplificamos con un token de 32 caracteres para que se vea; en 6 dígitos la fuga es
pequeña, pero como `compare_digest` no cuesta nada, no hay excusa para no usarlo. Por eso
en `verify` recorremos toda la ventana sin cortar."

## Slide 16 — E4 Fuerza bruta · *(M)* · 11:45–12:35

"Un código tiene un millón de valores, pero lo decisivo es **cuántos intentos por hora**
permitimos. Sin protección: 180 mil por hora, comprometido en horas. Con lockout: 12 por
hora; el tiempo esperado de un ataque exitoso pasa a más de **800 días**. Cuatro órdenes
de magnitud por una defensa simple."

## Slide 17 — E5 + E6 · *(M)* · 12:35–13:10

"El replay: un código vale **una vez**; reusarlo en su ventana se rechaza, gracias al
contador que devuelve `verify`. Y las 33 pruebas automatizadas pasan, desde los vectores
RFC hasta CSRF." *(Transición: "Alexander cierra con límites y aprendizajes.")*

## Slide 18 — Limitaciones · *(A)* · 13:10–13:55

"Somos honestos sobre los límites. TOTP es **phishable**: un sitio falso en tiempo real
reusa el código al instante; la defensa real es WebAuthn. La seguridad del secreto
depende de proteger la clave maestra. En la demo no hay HTTPS y el throttle es en
memoria. Y nada protege un dispositivo con malware."

## Slide 19 — Aprendizajes · *(A)* · 13:55–14:25

"El gran aprendizaje: lo difícil no es el happy path, son los detalles que deciden si
resiste un ataque —no cortar la ventana, `compare_digest`, devolver el contador. Hashing
no es cifrado: lo elegimos según el caso de uso. Y **medir** una defensa cambia la
confianza frente a solo suponer que funciona. Como futuro: WebAuthn, throttle distribuido
y KMS."

## Slide 20 — Cierre / Q&A · *(A+M)* · 14:25+

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
estrictamente mayores. Ese contador es justo el que devuelve `verify`. Es monotónico y no
depende de que el reloj sea perfecto.

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
