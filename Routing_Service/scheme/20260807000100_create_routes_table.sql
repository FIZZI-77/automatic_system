-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE routes (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 ticket_id uuid NOT NULL,
 brigade_id uuid NOT NULL,
 status text NOT NULL CHECK (
  status IN ('PLANNED', 'ACTIVE', 'COMPLETED', 'CANCELLED')
 ),
 origin jsonb NOT NULL,
 destination jsonb NOT NULL,
 waypoints jsonb NOT NULL DEFAULT '[]'::jsonb,
 options jsonb NOT NULL,
 calculation jsonb NOT NULL,
 revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS routes;
