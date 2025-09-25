-- create table (if not exists)
CREATE TABLE IF NOT EXISTS accounts (
    account_id       SERIAL PRIMARY KEY,
    name             VARCHAR(100) NOT NULL,
    mobile_number    VARCHAR(15) NOT NULL,
    email_id         VARCHAR(100) NOT NULL,
    role             VARCHAR(50) NOT NULL DEFAULT 'Worker' CHECK (role IN ('Worker','Admin','Manager')),
    password_hash    TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
);

-- enforce case-insensitive uniqueness for email (safer than plain UNIQUE)
CREATE UNIQUE INDEX IF NOT EXISTS accounts_email_ci_idx ON accounts (LOWER(email_id));

-- unique mobile number
CREATE UNIQUE INDEX IF NOT EXISTS accounts_mobile_unique_idx ON accounts (mobile_number);

-----------------------------------------------------------------------------------------------------------------------------------------

--Booking
CREATE TABLE bookings (
    booking_id       SERIAL PRIMARY KEY,              -- unique booking ID
    customer_name    VARCHAR(100) NOT NULL,           -- customer full name
    phone_number     VARCHAR(15) NOT NULL,            -- contact number
    number_of_persons INT NOT NULL CHECK (number_of_persons > 0),
    seat_type        VARCHAR(50) NOT NULL,            -- e.g., Regular, VIP
    total_hours      INT NOT NULL CHECK (total_hours > 0),
    booking_date     DATE NOT NULL,                   -- booking date
    booking_time     TIME NOT NULL,                   -- booking time
    price_per_person NUMERIC(10,2) NOT NULL CHECK (price_per_person >= 0),
    total_amount     NUMERIC(12,2) NOT NULL CHECK (total_amount >= 0),
    advance_amount   NUMERIC(12,2) DEFAULT 0 CHECK (advance_amount >= 0),
    proof_type       VARCHAR(50) NOT NULL,            -- Aadhaar / Passport / etc.
    proof_details    VARCHAR(100) NOT NULL,           -- ID number / details
    created_at       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-----------------------------------------------------------------------------------------------------------------------------------



