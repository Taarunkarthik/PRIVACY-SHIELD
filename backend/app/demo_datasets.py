"""The synthetic databases a hosted deployment creates for demonstration.

Every value is invented. Names are combined from short lists, addresses use
made-up streets, email addresses use the reserved example domains, and the
identity numbers only have the right shape. Nothing here describes a real
person, patient or student.

A dataset is one database with one source schema. ``statements`` creates its
tables and then fills them; it runs once, when ``probe`` does not exist yet.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class DemoDataset:
    database: str
    schema: str
    connection_name: str
    # A table in ``schema``; its presence means the fixtures were already created.
    probe: str
    statements: tuple[str, ...]


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

ENTERPRISE = DemoDataset(
    database="enterprise_demo",
    schema="enterprise",
    connection_name="Synthetic enterprise",
    probe="customers",
    statements=(
        "CREATE TABLE enterprise.customers ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "full_name text NOT NULL, email text NOT NULL UNIQUE, phone text, pan text,"
        "aadhaar text, address text, profile jsonb NOT NULL DEFAULT '{}'::jsonb,"
        "created_at timestamptz NOT NULL DEFAULT now())",
        "CREATE TABLE enterprise.accounts ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "customer_id bigint NOT NULL REFERENCES enterprise.customers(id),"
        "account_number text NOT NULL UNIQUE,"
        " balance numeric(14,2) NOT NULL CHECK (balance >= 0),"
        "currency char(3) NOT NULL DEFAULT 'INR')",
        "CREATE TABLE enterprise.transactions ("
        "account_id bigint NOT NULL REFERENCES enterprise.accounts(id),"
        "sequence_number integer NOT NULL CHECK (sequence_number > 0),"
        "amount numeric(14,2) NOT NULL, note text,"
        "PRIMARY KEY (account_id, sequence_number))",
        "CREATE TABLE enterprise.support_records ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "customer_id bigint NOT NULL REFERENCES enterprise.customers(id),"
        "related_account_id bigint, related_sequence_number integer, body text NOT NULL,"
        "FOREIGN KEY (related_account_id, related_sequence_number)"
        " REFERENCES enterprise.transactions(account_id, sequence_number))",
        "CREATE INDEX ix_accounts_customer_id ON enterprise.accounts(customer_id)",
        "CREATE INDEX ix_support_customer_id ON enterprise.support_records(customer_id)",
        "CREATE INDEX ix_support_transaction ON enterprise.support_records"
        "(related_account_id, related_sequence_number)",
        """
INSERT INTO enterprise.customers (full_name,email,phone,pan,aadhaar,address,profile)
SELECT 'Synthetic Customer ' || n,
       'customer' || n || '@example.com',
       '+91 90000 ' || lpad(n::text, 5, '0'),
       'ABCDE' || lpad(n::text,4,'0') || 'F',
       '2345 6789 ' || lpad(n::text,4,'0'),
       n || ' Example Street, Demo City',
       jsonb_build_object('contact', jsonb_build_object('email','alternate' || n || '@example.org'),
                          'preferences', jsonb_build_object('newsletter', n % 2 = 0))
FROM generate_series(1,100) AS n;
INSERT INTO enterprise.accounts(customer_id,account_number,balance)
SELECT id, 'DEMO' || lpad(id::text,12,'0'), id * 123.45 FROM enterprise.customers;
INSERT INTO enterprise.transactions(account_id,sequence_number,amount,note)
SELECT id, 1, 25.00, 'Synthetic payment reference' FROM enterprise.accounts;
INSERT INTO enterprise.support_records(customer_id,related_account_id,related_sequence_number,body)
SELECT id,id,1,'Please contact customer' || id || '@example.com about my demo account.'
FROM enterprise.customers;
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

# The first is the one every deployment has had; the others are added beside it.
DEMO_DATASETS = (ENTERPRISE, HOSPITAL, UNIVERSITY)
EXTRA_DATASETS = DEMO_DATASETS[1:]


def dataset_for(database: str) -> DemoDataset | None:
    return next((item for item in DEMO_DATASETS if item.database == database), None)
