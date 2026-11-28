"""Per-run canary test data: values that are unique to one capture, so they can be traced.

The PAN is a Luhn-valid number in the ``411111`` issuer range of the published Visa test card
``4111 1111 1111 1111``; it is never a real card. The other values are random tokens on
reserved names (``.invalid`` e-mail domain, RFC 2606), so nothing can ever be delivered to them.
"""

from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass

TEST_BIN = "411111"
CANARY_FIELDS = ("pan", "cvc", "expiry", "name", "email", "postcode", "phone", "token")


def luhn_check_digit(partial: str) -> str:
    """The digit that makes ``partial + digit`` pass the Luhn check."""
    total = 0
    for index, char in enumerate(reversed(partial)):
        digit = int(char)
        if index % 2 == 0:  # these positions are doubled once the check digit is appended
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return str((10 - total % 10) % 10)


def luhn_valid(number: str) -> bool:
    digits = [c for c in number if c.isdigit()]
    return len(digits) >= 12 and luhn_check_digit("".join(digits[:-1])) == digits[-1]


def _digits(count: int) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(count))


@dataclass(frozen=True)
class Canary:
    """One run's canary values. ``token`` is the random core shared by the text values."""

    pan: str
    cvc: str
    expiry: str
    name: str
    email: str
    postcode: str
    phone: str
    token: str

    @classmethod
    def generate(cls) -> Canary:
        body = TEST_BIN + _digits(9)
        token = secrets.token_hex(5)
        return cls(
            pan=body + luhn_check_digit(body),
            cvc=_digits(3),
            expiry=f"{1 + secrets.randbelow(12):02d}/{40 + secrets.randbelow(9)}",
            name=f"Canary {token.upper()}",
            email=f"canary-{token}@blink.invalid",
            postcode=f"BL{token[:4].upper()}",
            phone=f"+99{_digits(9)}",
            token=token,
        )

    def values(self) -> dict[str, str]:
        return asdict(self)
