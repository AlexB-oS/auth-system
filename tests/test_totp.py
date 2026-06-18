"""Conformidad de la implementación HOTP/TOTP con los vectores oficiales (E1).

- RFC 4226, Apéndice D: vectores de prueba HOTP.
- RFC 6238, Apéndice B: vectores de prueba TOTP (columna HMAC-SHA1).

Que estos vectores pasen es la evidencia más fuerte de que nuestra implementación
desde cero es correcta y, por construcción, interoperable con cualquier app
autenticadora estándar (Google/Microsoft Authenticator).
"""

import pytest

from auth import totp

# Secreto compartido de los RFC: ASCII "12345678901234567890" (20 bytes).
RFC_SECRET = b"12345678901234567890"

# RFC 4226, Apéndice D — HOTP de 6 dígitos.
HOTP_VECTORS = {
    0: "755224",
    1: "287082",
    2: "359152",
    3: "969429",
    4: "338314",
    5: "254676",
    6: "287922",
    7: "162583",
    8: "399871",
    9: "520489",
}

# RFC 6238, Apéndice B — TOTP de 8 dígitos con HMAC-SHA1 (período 30 s).
TOTP_SHA1_VECTORS = {
    59: "94287082",
    1111111109: "07081804",
    1111111111: "14050471",
    1234567890: "89005924",
    2000000000: "69279037",
    20000000000: "65353130",
}


@pytest.mark.parametrize("counter,expected", HOTP_VECTORS.items())
def test_hotp_rfc4226(counter, expected):
    assert totp.hotp(RFC_SECRET, counter, digits=6, algorithm="sha1") == expected


@pytest.mark.parametrize("t,expected", TOTP_SHA1_VECTORS.items())
def test_totp_rfc6238_sha1(t, expected):
    assert totp.totp(RFC_SECRET, for_time=t, period=30, digits=8, algorithm="sha1") == expected


def test_base32_roundtrip():
    secret = totp.generate_secret()
    assert totp.b32decode(totp.b32encode(secret)) == secret


def test_base32_tolerates_spaces_and_lowercase():
    secret = totp.generate_secret()
    b32 = totp.b32encode(secret)
    spaced = " ".join(b32[i : i + 4] for i in range(0, len(b32), 4)).lower()
    assert totp.b32decode(spaced) == secret


def test_verify_accepts_current_and_window():
    secret = totp.generate_secret()
    t = 1_700_000_000
    code = totp.totp(secret, for_time=t, period=30, digits=6)
    # Código del paso actual.
    assert totp.verify(secret, code, for_time=t, window=1) == t // 30
    # Tolerancia: un código del paso anterior sigue siendo válido con window=1.
    prev_code = totp.totp(secret, for_time=t - 30, period=30, digits=6)
    assert totp.verify(secret, prev_code, for_time=t, window=1) == (t // 30) - 1


def test_verify_rejects_outside_window():
    secret = totp.generate_secret()
    t = 1_700_000_000
    old_code = totp.totp(secret, for_time=t - 300, period=30, digits=6)
    assert totp.verify(secret, old_code, for_time=t, window=1) is None


def test_verify_rejects_wrong_code():
    secret = totp.generate_secret()
    assert totp.verify(secret, "000000", for_time=1_700_000_000, window=1) is None or True
    # Comparación robusta: un código aleatorio distinto del correcto debe fallar.
    t = 1_700_000_000
    correct = totp.totp(secret, for_time=t, digits=6)
    wrong = "000000" if correct != "000000" else "111111"
    assert totp.verify(secret, wrong, for_time=t, window=1) is None


def test_provisioning_uri_format():
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "alex", "IIC2531", digits=6, period=30)
    assert uri.startswith("otpauth://totp/IIC2531:alex?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=IIC2531" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri and "period=30" in uri
