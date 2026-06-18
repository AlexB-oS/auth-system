## Propuesta de Proyecto - Sistema de Autenticación IIC2531 Miguel Ulloa Wood Alexander Burgos Quezada 

Se eligió el caso del sistema de autenticación de contraseña y TOTP. Se realizará un servidor http que funciona en local, no deployado, en Python con Flask. Guardará la contraseña hasheada con Bcrypt. Y luego se implementara con una función HMAC-SHA1, un TOTP que genere códigos de 6 dígitos que se actualizan cada 30 segundos. 

Basándonos en el artículo de la página Digital Bunker, que explica el algoritmo, se realizará el algoritmo siguiendo los pasos de la página. 

Las piezas de software a implementar son las siguientes: 

1.-Una base de datos local con SqlLite, que guarda las cuentas, con secretos hasheados con Bcrypt. 

2.-Las funciones que manejan las cuentas y contraseñas de manera segura en el servidor, usando Flask. 

3.-Una función HMAC-SHA1 con las librerías hmac y hashlib para generar el código de 6 dígitos del TOTP. 

4.- Bloquear la cuenta por unos minutos luego de varios intentos de login seguidos, para los ataques de fuerza bruta. 

5.- Usar la función compare_digest de hmac, que según la documentación de la librería hmac de Python, previene timings attacks. 

6.- Una interfaz simple de login, en javascript, que utiliza la librería qrcode.js para mostrar el qr enviado por el servidor. 

7.- Se utilizará una app, como Google Authenticator o Microsoft Authenticator, para testear y usar el proyecto. 

Fuentes 

https://docs.python.org/3/library/hmac.html https://digitalbunker.dev/how-do-time-based-one-time-password-totp-services-work/ 

