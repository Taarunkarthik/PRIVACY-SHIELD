"""The synthetic databases a hosted deployment creates for demonstration.

Every value is invented. Names are combined from short lists, addresses use
made-up streets, email addresses use the reserved example domains, and the
identity numbers only have the right shape. Nothing here describes a real
person, patient or student.

A dataset is one database with one source schema. ``statements`` creates its
tables and then fills them; it runs once, when ``probe`` does not exist yet.
"""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class DemoDataset:
    database: str
    schema: str
    connection_name: str
    # A table in ``schema``; its presence means the fixtures were already created.
    probe: str
    statements: tuple[str, ...]
    scenario: Literal["sensitive", "masked", "vulnerable", "basic"] = "sensitive"


# Shared building blocks, written once so the three datasets read alike.
_FIRST = (
    "ARRAY['Aarav','Diya','Kabir','Ananya','Rohan','Meera','Arjun','Isha','Vikram','Neha',"
    "'Rahul','Priya','Dev','Kavya','Aditya','Sana','Nikhil','Tara','Imran','Lakshmi']"
)
_LAST = (
    "ARRAY['Sharma','Iyer','Khan','Reddy','Mehta','Nair','Gupta','Das','Pillai','Verma',"
    "'Joshi','Menon','Bose','Rao','Kapoor','Fernandes','Singh']"
)
_STREET = "ARRAY['MG Road','Park Street','Lake View Road','Temple Street','Station Road']"
_CITY = "ARRAY['Bengaluru','Kolkata','Chennai','Pune','Hyderabad','Kochi','Jaipur']"
# Seventeen and twenty share no factor, so the name pairs do not repeat within 100 rows.
_NAME = f"({_FIRST})[1 + n % 20] || ' ' || ({_LAST})[1 + n % 17]"
_HANDLE = f"lower(({_FIRST})[1 + n % 20]) || '.' || lower(({_LAST})[1 + n % 17]) || n"
_PHONE = (
    "'+91 9' || lpad((8000 + n * 37 % 2000)::text, 4, '0') || ' '"
    " || lpad((n * 7919 % 100000)::text, 5, '0')"
)
# Twelve digits in three groups, first digit 2 to 9: the shape of an Aadhaar number.
_AADHAAR = (
    "(2 + n % 8)::text || lpad((n * 131 % 1000)::text, 3, '0') || ' '"
    " || lpad((n * 4391 % 10000)::text, 4, '0') || ' ' || lpad((n * 977 % 10000)::text, 4, '0')"
)
_ADDRESS = f"(10 + n) || ' ' || ({_STREET})[1 + n % 5] || ', ' || ({_CITY})[1 + n % 7]"

# The enterprise dataset is the one the demo walks through, so it carries a small
# bank's proportions: 200 customers, 260 accounts, 3,900 transactions and 240
# tickets. Its value forms stay fixed on purpose (one email form, one phone form,
# one PAN form) because the scan stores shapes and the evidence test asserts them.
_ENT_FIRST = (
    "ARRAY['Aarav','Diya','Kabir','Ananya','Rohan','Meera','Arjun','Isha','Vikram','Neha',"
    "'Rahul','Priya','Dev','Kavya','Aditya','Sana','Nikhil','Tara','Imran','Lakshmi',"
    "'Farhan','Sneha','Manish','Pooja','Karan','Anjali','Sameer','Ritu','Yash','Divya',"
    "'Harish','Shreya','Naveen','Aisha','Gaurav','Nandini','Siddharth','Rupali','Ajay','Zoya']"
)
_ENT_LAST = (
    "ARRAY['Sharma','Iyer','Khan','Reddy','Mehta','Nair','Gupta','Das','Pillai','Verma',"
    "'Joshi','Menon','Bose','Rao','Kapoor','Fernandes','Singh','Chatterjee','Bhat','Desai',"
    "'Kulkarni','Malhotra','Patel','Saha','Sinha','Thakur','Varghese','Yadav','Ahuja','Banerjee']"
)
_ENT_NAME = f"({_ENT_FIRST})[1 + n % 40] || ' ' || ({_ENT_LAST})[1 + n % 30]"
# No dot in the local part, so the stored form stays a+9+@a+.a+.
_ENT_EMAIL = (
    f"lower(({_ENT_FIRST})[1 + n % 40]) || lower(({_ENT_LAST})[1 + n % 30])"
    " || n || '@example.com'"
)


def _ent_phone(column: str) -> str:
    """The demo's mobile form; ``column`` is the SQL expression holding the row id."""
    return (
        f"'+91 ' || (ARRAY['6','7','8','9'])[1 + {column} % 4]"
        f" || lpad(({column} * 37 % 10000)::text, 4, '0') || ' '"
        f" || lpad(({column} * 7919 % 100000)::text, 5, '0')"
    )


_ENT_PHONE = _ent_phone("n")
# The fourth letter is a holder type (P for person), so the recognizer scores a
# structural PAN candidate rather than a bare shape that needs column context.
_ENT_PAN = (
    "'AKJ' || 'P' || chr(65 + n % 26) || lpad((n * 419 % 10000)::text, 4, '0')"
    " || chr(65 + (n * 7) % 26)"
)
_ENT_AADHAAR = (
    "(2 + n % 8)::text || lpad((n * 131 % 1000)::text, 3, '0') || ' '"
    " || lpad((n * 4391 % 10000)::text, 4, '0') || ' ' || lpad((n * 977 % 10000)::text, 4, '0')"
)
_ENT_ADDRESS = (
    "(10 + n) || ' ' || (ARRAY['MG Road','Park Street','Lake View Road','Temple Street',"
    "'Station Road'])[1 + n % 5] || ', ' || (ARRAY['Bengaluru','Kolkata','Chennai','Pune',"
    "'Hyderabad','Kochi','Jaipur'])[1 + n % 7] || ' '"
    " || lpad(((ARRAY[560001,700001,600001,411001,500001,682001,302001])[1 + n % 7]"
    " + n * 37 % 900)::text, 6, '0')"
)

ENTERPRISE = DemoDataset(
    database="enterprise_demo",
    schema="enterprise",
    connection_name="Synthetic enterprise",
    probe="customers",
    statements=(
        "CREATE TABLE enterprise.customers ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "full_name text NOT NULL, email text NOT NULL UNIQUE, phone text, pan text,"
        "aadhaar text, address text, date_of_birth date NOT NULL,"
        "profile jsonb NOT NULL DEFAULT '{}'::jsonb,"
        "created_at timestamptz NOT NULL DEFAULT now())",
        "CREATE TABLE enterprise.accounts ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "customer_id bigint NOT NULL REFERENCES enterprise.customers(id),"
        "account_number text NOT NULL UNIQUE,"
        " balance numeric(14,2) NOT NULL CHECK (balance >= 0),"
        "currency char(3) NOT NULL DEFAULT 'INR', opened_on date NOT NULL)",
        "CREATE TABLE enterprise.transactions ("
        "account_id bigint NOT NULL REFERENCES enterprise.accounts(id),"
        "sequence_number integer NOT NULL CHECK (sequence_number > 0),"
        "posted_at timestamptz NOT NULL, amount numeric(14,2) NOT NULL, note text,"
        "PRIMARY KEY (account_id, sequence_number))",
        "CREATE TABLE enterprise.support_records ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "customer_id bigint NOT NULL REFERENCES enterprise.customers(id),"
        "related_account_id bigint, related_sequence_number integer,"
        "opened_at timestamptz NOT NULL, resolved boolean NOT NULL DEFAULT false,"
        "body text NOT NULL,"
        "FOREIGN KEY (related_account_id, related_sequence_number)"
        " REFERENCES enterprise.transactions(account_id, sequence_number))",
        "CREATE INDEX ix_accounts_customer_id ON enterprise.accounts(customer_id)",
        "CREATE INDEX ix_support_customer_id ON enterprise.support_records(customer_id)",
        "CREATE INDEX ix_support_transaction ON enterprise.support_records"
        "(related_account_id, related_sequence_number)",
        f"""
INSERT INTO enterprise.customers
  (full_name,email,phone,pan,aadhaar,address,date_of_birth,profile)
SELECT {_ENT_NAME},
       {_ENT_EMAIL},
       {_ENT_PHONE},
       {_ENT_PAN},
       {_ENT_AADHAAR},
       {_ENT_ADDRESS},
       date '1965-01-01' + (n * 7919 % 16000),
       jsonb_build_object(
         'contact', jsonb_build_object(
           'email', 'alt' || n || '@example.org',
           'phone', {_ENT_PHONE}),
         'preferences', jsonb_build_object('newsletter', n % 3 = 0))
FROM generate_series(1,200) AS n;
INSERT INTO enterprise.accounts (customer_id,account_number,balance,currency,opened_on)
SELECT id, '5010' || lpad((id * 7919 % 100000000)::text, 8, '0'),
       (1000 + (id * id * id * 7919 % 25000000)) / 100.0,
       (ARRAY['INR','INR','INR','INR','INR','USD','EUR'])[1 + id % 7],
       date '2015-01-01' + (id * 7919 % 3600)::int
FROM enterprise.customers;
INSERT INTO enterprise.accounts (customer_id,account_number,balance,currency,opened_on)
SELECT id, '5020' || lpad((id * 15485863 % 100000000)::text, 8, '0'),
       (1000 + (id * id * 65537 % 12000000)) / 100.0,
       'INR',
       date '2019-06-01' + (id * 1187 % 2000)::int
FROM enterprise.customers WHERE id <= 60;
INSERT INTO enterprise.transactions (account_id,sequence_number,posted_at,amount,note)
SELECT a.id, k,
       now() - ((a.id * 37 + k * 11) % 700) * interval '1 hour',
       (2000 + (a.id * 7919 + k * k * 104729) % 15000000) / 100.0,
       CASE
         WHEN (a.id + k) % 10 < 6 THEN
           'UPI/P2M/' || (100000000000 + (a.id * 1000003 + k * k * 7919) % 900000000000)::text
           || '/' || (ARRAY['SWIGGY','ZOMATO','AMAZON','BIGBASKET','IRCTC','AIRTEL',
                           'UBER','MYNTRA'])[1 + (a.id + k) % 8]
           || '/' || (ARRAY['HDFC','ICICI','SBI','AXIS'])[1 + (a.id + k) % 4]
         WHEN (a.id + k) % 10 < 8 THEN
           'ATM WDL ' || (100000000000 + (a.id * 1000003 + k * k * 7919) % 900000000000)::text
           || ' ' || (ARRAY['Bengaluru','Kolkata','Chennai','Pune','Hyderabad','Kochi',
                           'Jaipur'])[1 + (a.id + k) % 7]
         WHEN (a.id + k) % 10 < 9 THEN
           'NEFT CR ' || (ARRAY['HDFC','ICICI','SBI','AXIS'])[1 + (a.id + k) % 4]
           || (100000000000 + (a.id * 1000003 + k * k * 7919) % 900000000000)::text || ' SALARY'
         ELSE
           'IMPS P2A ' || (100000000000 + (a.id * 1000003 + k * k * 7919) % 900000000000)::text
           || ' RENT'
       END
FROM enterprise.accounts AS a
CROSS JOIN generate_series(1,15) AS k;
INSERT INTO enterprise.support_records
  (customer_id,related_account_id,related_sequence_number,opened_at,resolved,body)
SELECT c.id, a.id, 1 + c.id % 15,
       now() - (c.id % 240) * interval '3 hour',
       c.id % 3 = 0,
       'Ticket SR-' || lpad(c.id::text, 5, '0') || ': ' ||
       CASE
         WHEN c.id % 2 = 0 THEN 'please update the contact details on my account'
         WHEN c.id % 4 = 1 THEN 'the card ending 4412 was charged twice for the same order'
         WHEN c.id % 8 = 3 THEN 'call me on ' || {_ent_phone("c.id")}
              || ' before the next statement'
         WHEN c.id % 8 = 7 THEN 'send the receipt to alt' || c.id || '@example.org please'
         ELSE 'my address has changed and the cheque book has not arrived'
       END
       || ' Reference SR-' || lpad(c.id::text, 5, '0') || '.'
FROM enterprise.customers AS c
JOIN enterprise.accounts AS a
  ON a.customer_id = c.id AND a.account_number LIKE '5010%';
INSERT INTO enterprise.support_records
  (customer_id,related_account_id,related_sequence_number,opened_at,resolved,body)
SELECT c.id, a.id, 2 + c.id % 14,
       now() - ((c.id + 40) % 240) * interval '3 hour',
       false,
       'Ticket SR-' || lpad((c.id + 200)::text, 5, '0') || ': '
       || 'please update the contact details on my account'
       || ' Reference SR-' || lpad((c.id + 200)::text, 5, '0') || '.'
FROM enterprise.customers AS c
JOIN enterprise.accounts AS a
  ON a.customer_id = c.id AND a.account_number LIKE '5010%'
WHERE c.id <= 40;
""",
    ),
)

HOSPITAL = DemoDataset(
    database="hospital_demo",
    schema="hospital",
    connection_name="Synthetic hospital",
    probe="patients",
    statements=(
        "CREATE TABLE hospital.patients ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "full_name text NOT NULL, email text NOT NULL UNIQUE, phone text, aadhaar text,"
        "date_of_birth date NOT NULL, blood_group text, address text,"
        "emergency_contact jsonb NOT NULL DEFAULT '{}'::jsonb,"
        "registered_at timestamptz NOT NULL DEFAULT now())",
        "CREATE TABLE hospital.doctors ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "full_name text NOT NULL, email text NOT NULL UNIQUE, phone text,"
        "registration_number text NOT NULL UNIQUE, specialty text NOT NULL)",
        "CREATE TABLE hospital.appointments ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "patient_id bigint NOT NULL REFERENCES hospital.patients(id),"
        "doctor_id bigint NOT NULL REFERENCES hospital.doctors(id),"
        "scheduled_at timestamptz NOT NULL, reason text NOT NULL, notes text)",
        "CREATE TABLE hospital.billing ("
        "appointment_id bigint NOT NULL REFERENCES hospital.appointments(id),"
        "line_number integer NOT NULL CHECK (line_number > 0),"
        "amount numeric(12,2) NOT NULL CHECK (amount >= 0),"
        "card_number text, insurance_policy text,"
        "PRIMARY KEY (appointment_id, line_number))",
        "CREATE INDEX ix_appointments_patient_id ON hospital.appointments(patient_id)",
        "CREATE INDEX ix_appointments_doctor_id ON hospital.appointments(doctor_id)",
        f"""
INSERT INTO hospital.patients
  (full_name,email,phone,aadhaar,date_of_birth,blood_group,address,emergency_contact)
SELECT {_NAME},
       {_HANDLE} || '@example.com',
       {_PHONE},
       {_AADHAAR},
       date '1950-01-01' + (n * 211 % 20000),
       (ARRAY['A+','A-','B+','B-','O+','O-','AB+','AB-'])[1 + n % 8],
       {_ADDRESS},
       jsonb_build_object(
         'name', ({_FIRST})[1 + (n + 7) % 20] || ' ' || ({_LAST})[1 + n % 17],
         'phone', '+91 97' || lpad((n * 53 % 1000)::text, 3, '0') || ' '
                  || lpad((n * 6131 % 100000)::text, 5, '0'))
FROM generate_series(1,100) AS n;
INSERT INTO hospital.doctors (full_name,email,phone,registration_number,specialty)
SELECT 'Dr. ' || ({_FIRST})[1 + (n * 3) % 20] || ' ' || ({_LAST})[1 + (n * 5) % 17],
       'dr.' || lower(({_LAST})[1 + (n * 5) % 17]) || n || '@example.org',
       '+91 96' || lpad((n * 71 % 1000)::text, 3, '0') || ' '
         || lpad((n * 4447 % 100000)::text, 5, '0'),
       'REG-' || lpad((n * 1009)::text, 6, '0'),
       (ARRAY['Cardiology','Orthopaedics','Paediatrics','Dermatology',
              'General medicine'])[1 + n % 5]
FROM generate_series(1,10) AS n;
INSERT INTO hospital.appointments (patient_id,doctor_id,scheduled_at,reason,notes)
SELECT p.id, 1 + p.id % 10, now() - (p.id || ' days')::interval,
       (ARRAY['Annual check-up','Follow-up visit','Vaccination','Knee pain',
              'Skin rash'])[1 + p.id % 5],
       CASE WHEN p.id % 3 = 0
            THEN 'Patient asked for a call back on ' || p.phone || ' before the next visit.'
            WHEN p.id % 3 = 1
            THEN 'Send the report to ' || p.email || '.'
            ELSE 'No follow-up needed.' END
FROM hospital.patients AS p;
INSERT INTO hospital.billing (appointment_id,line_number,amount,card_number,insurance_policy)
SELECT a.id, 1, 500 + a.id * 12.50,
       (ARRAY['4111 1111 1111 1111','5500 0000 0000 0004','4012 8888 8888 1881',
              '5105 1051 0510 5100'])[1 + a.id % 4],
       'POL-' || lpad((a.id * 7331)::text, 9, '0')
FROM hospital.appointments AS a;
""",
    ),
)

UNIVERSITY = DemoDataset(
    database="university_demo",
    schema="university",
    connection_name="Synthetic university",
    probe="students",
    statements=(
        "CREATE TABLE university.students ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "roll_number text NOT NULL UNIQUE, full_name text NOT NULL,"
        "email text NOT NULL UNIQUE, phone text, aadhaar text, date_of_birth date NOT NULL,"
        "address text, guardian jsonb NOT NULL DEFAULT '{}'::jsonb,"
        "enrolled_at timestamptz NOT NULL DEFAULT now())",
        "CREATE TABLE university.faculty ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "full_name text NOT NULL, email text NOT NULL UNIQUE, phone text, pan text,"
        "department text NOT NULL)",
        "CREATE TABLE university.enrollments ("
        "student_id bigint NOT NULL REFERENCES university.students(id),"
        "course_code text NOT NULL, semester integer NOT NULL CHECK (semester BETWEEN 1 AND 8),"
        "faculty_id bigint NOT NULL REFERENCES university.faculty(id), grade text,"
        "PRIMARY KEY (student_id, course_code))",
        "CREATE TABLE university.fee_payments ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "student_id bigint NOT NULL REFERENCES university.students(id),"
        "amount numeric(12,2) NOT NULL CHECK (amount >= 0),"
        "bank_account_number text NOT NULL, paid_at timestamptz NOT NULL DEFAULT now(),"
        "remarks text)",
        "CREATE INDEX ix_enrollments_faculty_id ON university.enrollments(faculty_id)",
        "CREATE INDEX ix_fee_payments_student_id ON university.fee_payments(student_id)",
        f"""
INSERT INTO university.students
  (roll_number,full_name,email,phone,aadhaar,date_of_birth,address,guardian)
SELECT '26CS' || lpad(n::text, 4, '0'),
       {_NAME},
       {_HANDLE} || '@students.example.org',
       {_PHONE},
       {_AADHAAR},
       date '2003-01-01' + (n * 37 % 1800),
       {_ADDRESS},
       jsonb_build_object(
         'name', ({_FIRST})[1 + (n + 11) % 20] || ' ' || ({_LAST})[1 + n % 17],
         'email', 'guardian' || n || '@example.net')
FROM generate_series(1,100) AS n;
INSERT INTO university.faculty (full_name,email,phone,pan,department)
SELECT 'Prof. ' || ({_FIRST})[1 + (n * 7) % 20] || ' ' || ({_LAST})[1 + (n * 3) % 17],
       'prof.' || lower(({_LAST})[1 + (n * 3) % 17]) || n || '@example.org',
       '+91 95' || lpad((n * 89 % 1000)::text, 3, '0') || ' '
         || lpad((n * 5557 % 100000)::text, 5, '0'),
       'ABCP' || chr(65 + n % 26) || lpad((n * 419 % 10000)::text, 4, '0')
         || chr(65 + (n * 7) % 26),
       (ARRAY['Computer Science','Mathematics','Physics','Economics'])[1 + n % 4]
FROM generate_series(1,12) AS n;
INSERT INTO university.enrollments (student_id,course_code,semester,faculty_id,grade)
SELECT s.id, (ARRAY['CS301','MA201','PH101','EC210'])[1 + s.id % 4], 1 + s.id % 8,
       1 + s.id % 12, (ARRAY['A','B','C','D'])[1 + s.id % 4]
FROM university.students AS s;
INSERT INTO university.fee_payments (student_id,amount,bank_account_number,remarks)
SELECT s.id, 45000 + s.id * 10,
       'ACC' || lpad((s.id * 104729)::text, 13, '0'),
       CASE WHEN s.id % 4 = 0
            THEN 'Receipt emailed to ' || s.email || '.'
            ELSE 'Paid by bank transfer.' END
FROM university.students AS s;
""",
    ),
)


def _copy_schema(statements: tuple[str, ...], source: str, destination: str) -> tuple[str, ...]:
    """Copy one reviewed fixture to a fixed sibling schema."""
    return tuple(statement.replace(source + ".", destination + ".") for statement in statements)


MASKED = DemoDataset(
    database="masked_demo",
    schema="masked",
    connection_name="Masked policy lab",
    probe="customers",
    statements=_copy_schema(ENTERPRISE.statements, "enterprise", "masked"),
    scenario="masked",
)

VULNERABLE = DemoDataset(
    database="vulnerability_demo",
    schema="exposed",
    connection_name="Vulnerability lab",
    probe="customers",
    statements=_copy_schema(ENTERPRISE.statements, "enterprise", "exposed"),
    scenario="vulnerable",
)

BASIC = DemoDataset(
    database="basic_demo",
    schema="inventory",
    connection_name="Basic inventory",
    probe="products",
    statements=(
        "CREATE TABLE inventory.categories ("
        "id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text NOT NULL UNIQUE)",
        "CREATE TABLE inventory.suppliers ("
        "id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "
        "name text NOT NULL, tier text NOT NULL)",
        "CREATE TABLE inventory.products ("
        "id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "
        "category_id integer NOT NULL REFERENCES inventory.categories(id), "
        "supplier_id integer NOT NULL REFERENCES inventory.suppliers(id), "
        "name text NOT NULL, unit_price numeric(10,2) NOT NULL CHECK (unit_price >= 0))",
        "CREATE TABLE inventory.orders ("
        "id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "
        "product_id integer NOT NULL REFERENCES inventory.products(id), "
        "quantity integer NOT NULL CHECK (quantity > 0), ordered_at date NOT NULL)",
        "CREATE INDEX ix_products_category ON inventory.products(category_id)",
        "CREATE INDEX ix_products_supplier ON inventory.products(supplier_id)",
        """
INSERT INTO inventory.categories(name)
SELECT (ARRAY['Office','Kitchen','Outdoor','Electronics','Storage'])[1 + n % 5]
       || ' ' || n FROM generate_series(1, 20) AS n;
INSERT INTO inventory.suppliers(name,tier)
SELECT 'Supplier ' || n,
       (ARRAY['bronze','silver','gold','platinum'])[1 + n % 4]
FROM generate_series(1, 20) AS n;
INSERT INTO inventory.products(category_id,supplier_id,name,unit_price)
SELECT 1 + n % 20, 1 + (n * 7) % 20,
       (ARRAY['Desk lamp','Travel mug','Storage box','Notebook','Garden chair'])[1 + n % 5]
       || ' ' || n, (n * 137 % 25000)::numeric / 100 + 1
FROM generate_series(1, 100) AS n;
INSERT INTO inventory.orders(product_id,quantity,ordered_at)
SELECT id, 1 + id % 8, date '2025-01-01' + id FROM inventory.products;
""",
    ),
    scenario="basic",
)

# The first is the one every deployment has had; further databases are added beside it.
DEMO_DATASETS = (ENTERPRISE, HOSPITAL, UNIVERSITY, MASKED, VULNERABLE, BASIC)
EXTRA_DATASETS = DEMO_DATASETS[1:]


def dataset_for(database: str) -> DemoDataset | None:
    return next((item for item in DEMO_DATASETS if item.database == database), None)
