CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  email         VARCHAR(254) UNIQUE,
  username      VARCHAR(32) UNIQUE,
  display_name  VARCHAR(64) NOT NULL DEFAULT 'Anonymous',
  password_hash VARCHAR(255) NOT NULL,
  friend_code   CHAR(9) NOT NULL UNIQUE,
  lang          CHAR(2) NOT NULL DEFAULT 'en',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS messages (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  room        VARCHAR(64) NOT NULL DEFAULT 'global',
  text        VARCHAR(500) NOT NULL,
  title       VARCHAR(64),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_room_created ON messages(room, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_user_created ON messages(user_id, created_at);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'fr_status') THEN
    CREATE TYPE fr_status AS ENUM('pending','accepted','declined');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS friend_requests (
  id            BIGSERIAL PRIMARY KEY,
  from_user_id  BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status        fr_status NOT NULL DEFAULT 'pending',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  responded_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_one_open_req
  ON friend_requests(from_user_id, to_user_id, status);
