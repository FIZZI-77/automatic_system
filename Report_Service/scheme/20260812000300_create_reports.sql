-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE reports (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), requested_by uuid NOT NULL, name varchar(160) NOT NULL,
 type varchar(32) NOT NULL CHECK(type IN('TICKET_OVERVIEW','SLA_SUMMARY','TICKET_BREAKDOWN','DAILY_TICKETS')),
 format varchar(8) NOT NULL CHECK(format IN('PDF','XLSX','CSV')),
 status varchar(16) NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','PROCESSING','COMPLETED','FAILED','CANCELED')),
 filter jsonb NOT NULL DEFAULT '{}', file_id uuid, error text, attempts integer NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz
);
CREATE INDEX reports_requested_created_idx ON reports(requested_by,created_at DESC);
CREATE INDEX reports_pending_idx ON reports(created_at) WHERE status='PENDING';
CREATE TABLE outbox_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), aggregate_id uuid NOT NULL, event_type text NOT NULL, payload jsonb NOT NULL, status text NOT NULL DEFAULT 'PENDING', attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(), locked_at timestamptz, sent_at timestamptz, last_error text, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX report_outbox_pending_idx ON outbox_events(next_attempt_at,created_at) WHERE status IN('PENDING','FAILED');
-- +goose Down
DROP TABLE IF EXISTS outbox_events;
DROP TABLE IF EXISTS reports;
