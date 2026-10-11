"""A labelled synthetic benchmark for the PII detectors, scored per column.

Every value is fabricated from a fixed seed, and every column carries the answer
a careful reviewer would give it. The benchmark runs the real detector the scan
worker uses, aggregates rows into a column verdict the same way a scan does, and
reports precision and recall. It measures the deterministic detectors only; the
optional language model is not part of it.

Print the report with::

    python -m tests.support.pii_benchmark
"""

import random
import string
from dataclasses import dataclass

from app.services.policies.suggestions import dominant_category
from app.services.scanning.checks import verhoeff_valid
from app.services.scanning.sampling import Findings

NONE = "NONE"
ROWS_PER_COLUMN = 40
SEED = 20261011

_FIRST = (
    "Aarav", "Priya", "Rohan", "Ananya", "Vikram", "Sneha", "Arjun", "Kavya", "Rahul", "Meera",
    "James", "Emily", "Michael", "Sarah", "David", "Laura", "Daniel", "Olivia", "Fatima", "Imran",
)  # fmt: skip
_LAST = (
    "Sharma", "Patel", "Iyer", "Reddy", "Singh", "Nair", "Gupta", "Menon", "Khan", "Das",
    "Smith", "Johnson", "Brown", "Taylor", "Wilson", "Clark", "Lewis", "Walker", "Bose", "Roy",
)  # fmt: skip
_STREETS = ("MG Road", "Park Street", "Marine Drive", "Brigade Road", "Anna Salai", "Linking Road")
_CITIES = ("Bengaluru", "Mumbai", "Kolkata", "Chennai", "Pune", "Hyderabad", "Delhi", "Kochi")
_COMPANIES = (
    "Northwind Traders", "Blue Harbor Logistics", "Sunrise Textiles", "Vertex Analytics",
    "Evergreen Foods", "Silverline Systems", "Coastal Freight", "Pinnacle Retail",
)  # fmt: skip
_PRODUCTS = (
    "Wireless Mouse", "Steel Water Bottle", "Cotton Bedsheet", "LED Desk Lamp", "Notebook A5",
    "USB-C Cable", "Ceramic Mug", "Running Shoes", "Backpack 30L", "Bluetooth Speaker",
)  # fmt: skip
_STATUS = ("PENDING", "SHIPPED", "DELIVERED", "CANCELLED", "RETURNED")
_PAN_HOLDER_TYPES = "PCHFATBLJG"


def verhoeff_check_digit(digits: str) -> str:
    """The digit that makes ``digits`` pass the production Verhoeff check."""
    return next(d for d in string.digits if verhoeff_valid(digits + d))


def luhn_check_digit(digits: str) -> str:
    total = 0
    for index, digit in enumerate(reversed(digits)):
        value = int(digit) * (2 if index % 2 == 0 else 1)
        total += value - 9 if value > 9 else value
    return str((10 - total % 10) % 10)


@dataclass(frozen=True)
class Column:
    name: str
    label: str  # The expected category, or NONE for a column with no personal data.
    values: tuple[str, ...]
    note: str = ""


class _Factory:
    def __init__(self, seed: int):
        self.random = random.Random(seed)

    def digits(self, count: int) -> str:
        return "".join(self.random.choice(string.digits) for _ in range(count))

    def letters(self, count: int) -> str:
        return "".join(self.random.choice(string.ascii_uppercase) for _ in range(count))

    def name(self) -> str:
        return f"{self.random.choice(_FIRST)} {self.random.choice(_LAST)}"

    def email(self) -> str:
        first, last = self.random.choice(_FIRST).lower(), self.random.choice(_LAST).lower()
        domain = self.random.choice(("example.com", "example.org", "mail.example.net"))
        return f"{first}.{last}{self.random.randint(1, 99)}@{domain}"

    def indian_mobile(self) -> str:
        number = self.random.choice("6789") + self.digits(9)
        form = self.random.choice(("+91 {} {}", "+91-{}{}", "{}{}", "0{}{}"))
        return form.format(number[:5], number[5:])

    def us_phone(self) -> str:
        area = self.random.choice(("212", "415", "646", "312", "617"))
        return f"+1 ({area}) {self.random.randint(200, 999)}-{self.digits(4)}"

    def pan(self) -> str:
        return (
            self.letters(3)
            + self.random.choice(_PAN_HOLDER_TYPES)
            + self.letters(1)
            + self.digits(4)
            + self.letters(1)
        )

    def pan_shaped_code(self) -> str:
        # Five letters, four digits, one letter: the PAN shape with random letters,
        # so about 10 in 26 happen to carry a valid holder-type letter.
        return self.letters(5) + self.digits(4) + self.letters(1)

    def aadhaar(self, spaced: bool = True) -> str:
        body = self.random.choice("23456789") + self.digits(10)
        number = body + verhoeff_check_digit(body)
        return f"{number[:4]} {number[4:8]} {number[8:]}" if spaced else number

    def twelve_digit_id(self) -> str:
        # Twelve random digits. About one in ten passes the Aadhaar checksum.
        return self.random.choice("23456789") + self.digits(11)

    def card(self) -> str:
        body = self.random.choice(("4", "51", "52", "55")) + self.digits(14)
        body = body[:15]
        number = body + luhn_check_digit(body)
        return " ".join(number[i : i + 4] for i in range(0, 16, 4))

    def iban(self) -> str:
        # Valid GB IBANs: bank code, sort code, account, with computed check digits.
        bban = self.random.choice(("WEST", "NWBK", "BARC", "LOYD")) + self.digits(14)
        rearranged = "".join(str(int(c, 36)) for c in bban + "GB00")
        check = 98 - int(rearranged) % 97
        return f"GB{check:02d}{bban}"

    def account(self) -> str:
        return self.digits(self.random.choice((11, 12, 14, 16)))

    def address(self) -> str:
        return (
            f"{self.random.randint(1, 240)} {self.random.choice(_STREETS)}, "
            f"{self.random.choice(_CITIES)} {self.random.randint(400001, 700099)}"
        )

    def money(self) -> str:
        return f"{self.random.randint(50, 250000)}.{self.random.randint(0, 99):02d}"

    def date(self) -> str:
        year, month, day = self.pick(19, 26), self.pick(1, 12), self.pick(1, 28)
        return f"20{year}-{month:02d}-{day:02d}"

    def version(self) -> str:
        return f"{self.pick(1, 9)}.{self.pick(0, 20)}.{self.pick(0, 99)}"

    def pick(self, low: int, high: int) -> int:
        return self.random.randint(low, high)

    def uuid(self) -> str:
        raw = "".join(self.random.choice("0123456789abcdef") for _ in range(32))
        return f"{raw[:8]}-{raw[8:12]}-4{raw[13:16]}-a{raw[17:20]}-{raw[20:]}"


def build_columns(rows: int = ROWS_PER_COLUMN, seed: int = SEED) -> list[Column]:
    """Build the labelled columns. The same seed always gives the same data."""
    make = _Factory(seed)

    def column(name: str, label: str, generator, note: str = "") -> Column:
        return Column(name, label, tuple(generator() for _ in range(rows)), note)

    def sometimes(generator, filler, share: float):
        return lambda: generator() if make.random.random() < share else filler()

    plain_note = lambda: make.random.choice(  # noqa: E731
        ("Delivered on time.", "Customer requested invoice copy.", "Awaiting stock.", "No issues.")
    )
    return [
        # Emails, including a column whose name gives nothing away.
        column("email", "EMAIL_ADDRESS", make.email),
        column("contact_email", "EMAIL_ADDRESS", make.email),
        column("field_7", "EMAIL_ADDRESS", make.email, "uninformative column name"),
        column(
            "notes",
            "EMAIL_ADDRESS",
            sometimes(lambda: f"Please reply to {make.email()} about the refund.", plain_note, 0.3),
            "email in 30% of free-text rows",
        ),
        # Phone numbers in Indian and US formats.
        column("phone", "PHONE_NUMBER", make.indian_mobile),
        column("mobile_no", "PHONE_NUMBER", make.indian_mobile),
        column("contact_number", "PHONE_NUMBER", make.us_phone),
        column("alt_contact", "PHONE_NUMBER", make.indian_mobile, "uninformative column name"),
        # Indian identifiers with valid structure and checksums.
        column("pan", "PAN_CANDIDATE", make.pan),
        column("pan_number", "PAN_CANDIDATE", make.pan),
        column("tax_id", "PAN_CANDIDATE", make.pan, "name does not say PAN"),
        column("aadhaar", "AADHAAR_CANDIDATE", make.aadhaar),
        column("aadhaar_no", "AADHAAR_CANDIDATE", lambda: make.aadhaar(spaced=False)),
        column("id_proof_number", "AADHAAR_CANDIDATE", make.aadhaar, "name does not say Aadhaar"),
        # Financial identifiers.
        column("card_number", "CREDIT_CARD", make.card),
        column("payment_ref", "CREDIT_CARD", make.card, "name does not say card"),
        column("iban", "IBAN_CODE", make.iban),
        column("account_number", "BANK_ACCOUNT", make.account),
        column("bank_account_no", "BANK_ACCOUNT", make.account),
        # People and places.
        column("full_name", "PERSON", make.name),
        column("customer_name", "PERSON", make.name),
        column("contact_person", "PERSON", make.name, "name does not contain 'name'"),
        column("address", "LOCATION", make.address),
        column("shipping_address", "LOCATION", make.address),
        # Columns with no personal data, several chosen to look like identifiers.
        column("order_id", NONE, make.twelve_digit_id, "12 random digits, the Aadhaar length"),
        column("sku", NONE, make.pan_shaped_code, "PAN-shaped product code"),
        column(
            "tracking_no", NONE, lambda: "9" + make.digits(9), "10 digits, like a mobile number"
        ),
        column(
            "invoice_no", NONE, lambda: f"INV-{make.random.randint(2019, 2026)}-{make.digits(6)}"
        ),
        column("amount", NONE, make.money),
        column("quantity", NONE, lambda: str(make.random.randint(1, 500))),
        column("order_date", NONE, make.date),
        column("status", NONE, lambda: make.random.choice(_STATUS)),
        column("currency", NONE, lambda: make.random.choice(("INR", "USD", "EUR", "GBP"))),
        column("is_active", NONE, lambda: make.random.choice(("true", "false"))),
        column("session_id", NONE, make.uuid),
        column("product_name", NONE, lambda: make.random.choice(_PRODUCTS)),
        column(
            "company", NONE, lambda: make.random.choice(_COMPANIES), "organisation, not a person"
        ),
        column("city", NONE, lambda: make.random.choice(_CITIES), "a city alone identifies no one"),
        column("remarks", NONE, plain_note, "free text with no personal data"),
        column("app_version", NONE, make.version),
    ]


def predict(column: Column, detector) -> tuple[str, int]:
    """Aggregate row detections into one column verdict, exactly as a scan does."""
    findings = Findings()
    for value in column.values:
        findings.add_row(detector(value, column.name))
    return dominant_category(findings.category_counts) or NONE, findings.matching_rows


def evaluate(columns: list[Column], detector) -> dict:
    """Score the detector's column verdicts against the labels."""
    rows = []
    for column in columns:
        predicted, matching = predict(column, detector)
        rows.append({"column": column, "predicted": predicted, "matching_rows": matching})

    def score(expected: set[str], predicted_as: set[str]) -> dict:
        true_positive = sum(
            1 for r in rows if r["column"].label in expected and r["predicted"] in predicted_as
        )
        actual = sum(1 for r in rows if r["column"].label in expected)
        claimed = sum(1 for r in rows if r["predicted"] in predicted_as)
        precision = true_positive / claimed if claimed else 1.0
        recall = true_positive / actual if actual else 1.0
        return {
            "columns": actual,
            "flagged": claimed,
            "correct": true_positive,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
        }

    categories = sorted({r["column"].label for r in rows} - {NONE})
    sensitive = {r["column"].label for r in rows} | {r["predicted"] for r in rows}
    sensitive.discard(NONE)
    return {
        "rows": rows,
        "per_category": {category: score({category}, {category}) for category in categories},
        # Did the detector flag the column at all, whatever category it chose?
        "sensitive": score(sensitive, sensitive),
        "exact": round(sum(1 for r in rows if r["predicted"] == r["column"].label) / len(rows), 3),
    }


def report(result: dict) -> str:
    """Render the evaluation as Markdown."""
    lines = [
        "| Category | Labelled columns | Flagged | Correct | Precision | Recall |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for category, s in result["per_category"].items():
        lines.append(
            f"| `{category}` | {s['columns']} | {s['flagged']} | {s['correct']} "
            f"| {s['precision']:.2f} | {s['recall']:.2f} |"
        )
    s = result["sensitive"]
    lines += [
        f"| **Any personal data** | {s['columns']} | {s['flagged']} | {s['correct']} "
        f"| {s['precision']:.2f} | {s['recall']:.2f} |",
        "",
        f"Exact category on {result['exact']:.0%} of {len(result['rows'])} columns.",
        "",
        "| Column | Label | Detected | Matching rows | Note |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for r in result["rows"]:
        if r["predicted"] != r["column"].label:
            c = r["column"]
            lines.append(
                f"| `{c.name}` | `{c.label}` | `{r['predicted']}` "
                f"| {r['matching_rows']}/{len(c.values)} | {c.note} |"
            )
    return "\n".join(lines)


if __name__ == "__main__":
    from app.services.scanning.detection import detect_pii

    print(report(evaluate(build_columns(), detect_pii)))
