-- Tennis Court Booking — Database Schema
-- Run this once on your Neon (or any Postgres) database

CREATE TABLE IF NOT EXISTS users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  fname       TEXT NOT NULL,
  lname       TEXT NOT NULL,
  apt         TEXT NOT NULL,
  phone       TEXT UNIQUE NOT NULL,
  pin_hash    TEXT NOT NULL,
  is_admin    BOOLEAN DEFAULT false,
  approved    BOOLEAN DEFAULT false,
  created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bookings (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
  date        DATE NOT NULL,
  hour        SMALLINT NOT NULL CHECK (hour >= 6 AND hour <= 22),
  created_at  TIMESTAMPTZ DEFAULT now(),
  UNIQUE (date, hour),
  UNIQUE (user_id, date)   -- 1 booking per person per day
);

CREATE TABLE IF NOT EXISTS notifications (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type            TEXT NOT NULL,        -- 'reg' | 'book'
  text            TEXT NOT NULL,
  target_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
  target_date     DATE,
  target_hour     SMALLINT,
  read            BOOLEAN DEFAULT false,
  created_at      TIMESTAMPTZ DEFAULT now()
);

-- Create the admin user (run this once, change the phone/PIN to yours)
-- PIN below is '0000' hashed — change it immediately after first login!
INSERT INTO users (fname, lname, apt, phone, pin_hash, is_admin, approved)
VALUES (
  'Admin', '', '—', '000 0000000',
  '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.', -- bcrypt of '0000'
  true, true
)
ON CONFLICT (phone) DO NOTHING;
