-- All records below are fabricated fixtures, never customer data.
CREATE TABLE enterprise.customers (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  full_name text NOT NULL,
  email text NOT NULL UNIQUE,
  phone text,
  pan text,
  aadhaar text,
  address text,
  profile jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterprise.accounts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_id bigint NOT NULL REFERENCES enterprise.customers(id),
  account_number text NOT NULL UNIQUE,
  balance numeric(14,2) NOT NULL CHECK (balance >= 0),
  currency char(3) NOT NULL DEFAULT 'INR'
);
CREATE INDEX ix_accounts_customer_id ON enterprise.accounts(customer_id);
CREATE TABLE enterprise.transactions (
  account_id bigint NOT NULL REFERENCES enterprise.accounts(id),
  sequence_number integer NOT NULL CHECK (sequence_number > 0),
  amount numeric(14,2) NOT NULL,
  note text,
  PRIMARY KEY (account_id, sequence_number)
);
CREATE TABLE enterprise.support_records (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_id bigint NOT NULL REFERENCES enterprise.customers(id),
  related_account_id bigint,
  related_sequence_number integer,
  body text NOT NULL,
  FOREIGN KEY (related_account_id, related_sequence_number)
    REFERENCES enterprise.transactions(account_id, sequence_number)
);
CREATE INDEX ix_support_customer_id ON enterprise.support_records(customer_id);
CREATE INDEX ix_support_transaction ON enterprise.support_records(related_account_id, related_sequence_number);
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
SELECT id,id,1,'Please contact customer' || id || '@example.com about my demo account.' FROM enterprise.customers;
