"""Safe starter decisions for the synthetic masked-policy demonstration."""


_IDENTITY_COLUMNS = {
    "aadhaar",
    "account_number",
    "bank_account_number",
    "card_number",
    "pan",
    "registration_number",
    "roll_number",
}
_FREE_TEXT_COLUMNS = {
    "address",
    "body",
    "date_of_birth",
    "dob",
    "guardian",
    "note",
    "notes",
    "profile",
    "reason",
    "remarks",
}


def starter_policy_rules(columns: list[dict]) -> list[dict[str, str]]:
    """Build one explicit reader decision for every discovered column.

    Unknown columns default to KEEP so the demo is predictable; known PII and
    free-text fields are transformed or withheld. JSON values are nullified as
    a whole column until path-level policies are reviewed.
    """
    rules = []
    for column in columns:
        name = column["name"].lower()
        if column.get("is_jsonb") or name in _FREE_TEXT_COLUMNS:
            action = "NULLIFY"
        elif "email" in name:
            action = "MASK_EMAIL"
        elif "phone" in name or "mobile" in name:
            action = "MASK_PHONE"
        elif name in _IDENTITY_COLUMNS:
            action = "MASK_ID"
        elif "name" in name:
            action = "REDACT"
        else:
            action = "KEEP"
        rules.append({"column_name": column["name"], "action": action, "audience": "reader"})
    return rules
