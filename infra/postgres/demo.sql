-- All records below are fabricated fixtures, never customer data.
-- The forms are deliberately fixed: one email form, one phone form, one PAN
-- form. The scan stores value shapes, and the integration tests assert them.
CREATE TABLE enterprise.customers (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  full_name text NOT NULL,
  email text NOT NULL UNIQUE,
  phone text,
  pan text,
  aadhaar text,
  address text,
  date_of_birth date NOT NULL,
  profile jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterprise.accounts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_id bigint NOT NULL REFERENCES enterprise.customers(id),
  account_number text NOT NULL UNIQUE,
  balance numeric(14,2) NOT NULL CHECK (balance >= 0),
  currency char(3) NOT NULL DEFAULT 'INR',
  opened_on date NOT NULL
);
CREATE INDEX ix_accounts_customer_id ON enterprise.accounts(customer_id);
CREATE TABLE enterprise.transactions (
  account_id bigint NOT NULL REFERENCES enterprise.accounts(id),
  sequence_number integer NOT NULL CHECK (sequence_number > 0),
  posted_at timestamptz NOT NULL,
  amount numeric(14,2) NOT NULL,
  note text,
  PRIMARY KEY (account_id, sequence_number)
);
CREATE TABLE enterprise.support_records (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_id bigint NOT NULL REFERENCES enterprise.customers(id),
  related_account_id bigint,
  related_sequence_number integer,
  opened_at timestamptz NOT NULL,
  resolved boolean NOT NULL DEFAULT false,
  body text NOT NULL,
  FOREIGN KEY (related_account_id, related_sequence_number)
    REFERENCES enterprise.transactions(account_id, sequence_number)
);
CREATE INDEX ix_support_customer_id ON enterprise.support_records(customer_id);
CREATE INDEX ix_support_transaction ON enterprise.support_records(related_account_id, related_sequence_number);

INSERT INTO enterprise.customers
  (full_name,email,phone,pan,aadhaar,address,date_of_birth,profile)
SELECT (ARRAY['Aarav','Diya','Kabir','Ananya','Rohan','Meera','Arjun','Isha','Vikram','Neha',
              'Rahul','Priya','Dev','Kavya','Aditya','Sana','Nikhil','Tara','Imran','Lakshmi',
              'Farhan','Sneha','Manish','Pooja','Karan','Anjali','Sameer','Ritu','Yash','Divya',
              'Harish','Shreya','Naveen','Aisha','Gaurav','Nandini','Siddharth','Rupali','Ajay',
              'Zoya'])[1 + n % 40]
       || ' ' ||
       (ARRAY['Sharma','Iyer','Khan','Reddy','Mehta','Nair','Gupta','Das','Pillai','Verma',
              'Joshi','Menon','Bose','Rao','Kapoor','Fernandes','Singh','Chatterjee','Bhat',
              'Desai','Kulkarni','Malhotra','Patel','Saha','Sinha','Thakur','Varghese','Yadav',
              'Ahuja','Banerjee'])[1 + n % 30],
       lower((ARRAY['Aarav','Diya','Kabir','Ananya','Rohan','Meera','Arjun','Isha','Vikram','Neha',
                     'Rahul','Priya','Dev','Kavya','Aditya','Sana','Nikhil','Tara','Imran','Lakshmi',
                     'Farhan','Sneha','Manish','Pooja','Karan','Anjali','Sameer','Ritu','Yash','Divya',
                     'Harish','Shreya','Naveen','Aisha','Gaurav','Nandini','Siddharth','Rupali','Ajay',
                     'Zoya'])[1 + n % 40])
       || lower((ARRAY['Sharma','Iyer','Khan','Reddy','Mehta','Nair','Gupta','Das','Pillai','Verma',
                       'Joshi','Menon','Bose','Rao','Kapoor','Fernandes','Singh','Chatterjee','Bhat',
                       'Desai','Kulkarni','Malhotra','Patel','Saha','Sinha','Thakur','Varghese','Yadav',
                       'Ahuja','Banerjee'])[1 + n % 30])
       || n || '@example.com',
       '+91 ' || (ARRAY['6','7','8','9'])[1 + n % 4]
       || lpad((n * 37 % 10000)::text, 4, '0') || ' '
       || lpad((n * 7919 % 100000)::text, 5, '0'),
       'AKJ' || 'P' || chr(65 + n % 26) || lpad((n * 419 % 10000)::text, 4, '0')
       || chr(65 + (n * 7) % 26),
       (2 + n % 8)::text || lpad((n * 131 % 1000)::text, 3, '0') || ' '
       || lpad((n * 4391 % 10000)::text, 4, '0') || ' '
       || lpad((n * 977 % 10000)::text, 4, '0'),
       (10 + n) || ' ' ||
       (ARRAY['MG Road','Park Street','Lake View Road','Temple Street','Station Road'])[1 + n % 5]
       || ', ' ||
       (ARRAY['Bengaluru','Kolkata','Chennai','Pune','Hyderabad','Kochi','Jaipur'])[1 + n % 7]
       || ' ' || lpad(((ARRAY[560001,700001,600001,411001,500001,682001,302001])[1 + n % 7]
                      + n * 37 % 900)::text, 6, '0'),
       date '1965-01-01' + (n * 7919 % 16000),
       jsonb_build_object(
         'contact', jsonb_build_object(
           'email', 'alt' || n || '@example.org',
           'phone', '+91 ' || (ARRAY['6','7','8','9'])[1 + n % 4]
                    || lpad((n * 37 % 10000)::text, 4, '0') || ' '
                    || lpad((n * 7919 % 100000)::text, 5, '0')),
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
         WHEN c.id % 8 = 3 THEN 'call me on +91 ' || (ARRAY['6','7','8','9'])[1 + c.id % 4]
              || lpad((c.id * 37 % 10000)::text, 4, '0') || ' '
              || lpad((c.id * 7919 % 100000)::text, 5, '0') || ' before the next statement'
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
