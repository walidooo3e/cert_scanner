# analyzer.py
from enum import Enum

class Flag(Enum):
    EXPIRED        = "EXPIRED"
    CRITICAL       = "CRITICAL"
    WARNING        = "WARNING"
    SELF_SIGNED    = "SELF_SIGNED"
    WEAK_ALGORITHM = "WEAK_ALGORITHM"
    WEAK_KEY       = "WEAK_KEY"

class Severity(Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"
    OK     = "OK"

class Status(Enum):
    OK    = "OK"
    ERROR = "ERROR"


EXPIRY_CRITICAL_DAYS = 7
EXPIRY_WARNING_DAYS  = 30
RSA_MIN_BITS         = 2048
WEAK_HASH_ALGORITHMS = {"SHA1", "MD5"}


def analyze(cert: dict) -> list[Flag]:
    flags = []

    days = cert.get("days_to_expiry")
    if days is not None:
        if days < 0:
            flags.append(Flag.EXPIRED)
        elif days < EXPIRY_CRITICAL_DAYS:
            flags.append(Flag.CRITICAL)
        elif days < EXPIRY_WARNING_DAYS:
            flags.append(Flag.WARNING)

    if cert.get("self_signed"):
        flags.append(Flag.SELF_SIGNED)

    sig_alg = cert.get("signature_algorithm", "").upper()
    if any(weak in sig_alg for weak in WEAK_HASH_ALGORITHMS):
        flags.append(Flag.WEAK_ALGORITHM)

    if (
        cert.get("public_key_type", "").upper() == "RSA"
        and cert.get("public_key_bits") is not None
        and cert.get("public_key_bits") < RSA_MIN_BITS
    ):
        flags.append(Flag.WEAK_KEY)

    return flags


def severity(flags: list[Flag]) -> Severity:
    if Flag.EXPIRED in flags or Flag.WEAK_ALGORITHM in flags or Flag.WEAK_KEY in flags:
        return Severity.HIGH
    if Flag.CRITICAL in flags or Flag.SELF_SIGNED in flags:
        return Severity.MEDIUM
    if Flag.WARNING in flags:
        return Severity.LOW
    return Severity.OK