// UI mínima: facilita ingresar el código (numérico) y enfoca el primer campo.
// Servido como archivo estático (no inline) para cumplir con la CSP del servidor.
(function () {
  "use strict";
  document.querySelectorAll("input.code-input").forEach(function (el) {
    el.addEventListener("input", function () {
      // Para el QR/2FA el código es numérico; los de respaldo permiten letras y guion.
      if (el.getAttribute("pattern") === "[0-9]*") {
        el.value = el.value.replace(/[^0-9]/g, "").slice(0, 6);
      }
    });
  });
})();
