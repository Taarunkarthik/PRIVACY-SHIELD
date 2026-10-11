# Detection accuracy

PrivacyShield's detectors are measured against a labelled synthetic benchmark, so
"it finds PII" is a number that can be checked rather than a claim. This page
records how the benchmark works, what it measured, and where detection is wrong.

## What is measured

The benchmark is 40 synthetic columns of 40 values each, generated from a fixed
seed in [`backend/tests/support/pii_benchmark.py`](../backend/tests/support/pii_benchmark.py).
24 columns hold personal data and carry the category a reviewer would assign. 16
hold none, and several of those are built to resemble identifiers: twelve-digit
order numbers, product codes with the PAN shape, ten-digit tracking numbers.

Each column is run through the same detector the scan worker uses
(`detect_pii`), and row results are combined into one verdict per column the way
a scan combines them. A column counts as correct only when the detected category
equals its label.

Two numbers matter per category:

- **Recall**: of the columns that hold this category, the share the detector found.
  A miss here means personal data left unprotected, so it is the costlier error.
- **Precision**: of the columns the detector flagged as this category, the share
  that really hold it. A miss here means a reviewer is shown a column that needs
  no masking.

The benchmark covers the deterministic detectors only: Presidio recognisers, the
bundled spaCy model, column-name hints, and the checksum rules. The optional
language model is not part of it. Every value is fabricated, so the results say
nothing certain about any real database.

## Results

Measured on 11 October 2026 with `presidio-analyzer` 2.2.364 and
`en_core_web_sm` 3.8.0.

| Category | Labelled columns | Flagged | Correct | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| `AADHAAR_CANDIDATE` | 3 | 4 | 3 | 0.75 | 1.00 |
| `BANK_ACCOUNT` | 2 | 2 | 2 | 1.00 | 1.00 |
| `CREDIT_CARD` | 2 | 2 | 2 | 1.00 | 1.00 |
| `EMAIL_ADDRESS` | 4 | 4 | 4 | 1.00 | 1.00 |
| `IBAN_CODE` | 1 | 1 | 1 | 1.00 | 1.00 |
| `LOCATION` | 2 | 3 | 2 | 0.67 | 1.00 |
| `PAN_CANDIDATE` | 3 | 4 | 3 | 0.75 | 1.00 |
| `PERSON` | 3 | 5 | 3 | 0.60 | 1.00 |
| `PHONE_NUMBER` | 4 | 6 | 4 | 0.67 | 1.00 |
| **Any personal data** | 24 | 31 | 24 | 0.77 | 1.00 |

Exact category on 82% of 40 columns.

No column holding personal data was missed. About one flagged column in four
holds none, and every one of those is listed below.

## Where it is wrong

| Column | Label | Detected | Matching rows | Note |
| --- | --- | --- | ---: | --- |
| `order_id` | `NONE` | `AADHAAR_CANDIDATE` | 8/40 | 12 random digits, the Aadhaar length |
| `sku` | `NONE` | `PAN_CANDIDATE` | 21/40 | PAN-shaped product code |
| `tracking_no` | `NONE` | `PHONE_NUMBER` | 40/40 | 10 digits, like a mobile number |
| `invoice_no` | `NONE` | `PHONE_NUMBER` | 40/40 |  |
| `session_id` | `NONE` | `PERSON` | 3/40 |  |
| `product_name` | `NONE` | `PERSON` | 5/40 |  |
| `city` | `NONE` | `LOCATION` | 14/40 | a city alone identifies no one |

What these mean in practice:

- **`tracking_no`, `invoice_no`**: a ten-digit number starting with 9 is a valid
  Indian mobile number, and the phone recogniser also accepts the digits inside
  `INV-2024-123456`. Nothing in the value separates these from a phone number.
  A reviewer has to reject them by knowing what the column is.
- **`order_id`, `sku`**: about one random twelve-digit number in ten passes the
  Aadhaar checksum, and ten of the 26 letters are valid in a PAN's fourth
  position. The match rate gives these away: a real Aadhaar or PAN column matches
  on every row, while these match on a fraction.
- **`session_id`, `product_name`**: the small English language model reads a few
  values as person names.
- **`city`**: detected as a location, which it is. The benchmark labels it as not
  personal because a city alone identifies no one. This one is a judgement call.

The policy editor shows the match rate beside every suggestion for this reason.
A suggested mask can also hide a column that did not need hiding, which costs
utility but never exposes data.

## Effect of the checksum rules

The Aadhaar checksum (Verhoeff) and the PAN holder-type rule were added after the
first measurement. On the same 40 columns:

| | Before | After |
| --- | ---: | ---: |
| Aadhaar recall | 0.67 | 1.00 |
| Exact category | 80% | 82% |
| Product codes read as PAN (`sku`) | 40 of 40 rows | 21 of 40 rows |
| Aadhaar columns given the wrong category | 1 | 0 |

The gain is the `id_proof_number` column: valid Aadhaar numbers under a name that
does not say Aadhaar. Before, a twelve-digit number was only reported when the
word "Aadhaar" appeared nearby. Now a number with a valid check digit is reported
wherever it is. The cost is the `order_id` row above, which moved from a stray
phone match to a partial Aadhaar match.

## Run it

Inside the API container, or any environment with the backend dependencies:

```powershell
docker compose exec api python -m tests.support.pii_benchmark
```

It prints the tables above and takes about ten seconds. The same benchmark runs
in the unit test suite ([`test_detection_benchmark.py`](../backend/tests/test_detection_benchmark.py)),
which fails if any column with personal data is missed or if precision drops
below 0.75.

## Limits of this benchmark

- 40 columns is a small sample. A single column changes a category's precision
  by many points, so read the per-category figures as indications.
- The values are clean and consistently formatted. Real data has typos, mixed
  formats, and other languages, and detection will do worse on it.
- Names and addresses are Indian and Western English only.
- JSON documents are not included; nested values go through the same detector
  after the scanner flattens them.
