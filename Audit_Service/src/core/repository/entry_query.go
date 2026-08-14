package repository

import (
	"audit/models"
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const entryColumns = `id,event_id,topic,action,actor_id,entity_type,entity_id,request_id,trace_id,data,occurred_at,recorded_at`

type EntryReaderRepoStruct struct{ db *pgxpool.Pool }

func NewEntryReaderRepoStruct(db *pgxpool.Pool) *EntryReaderRepoStruct {
	return &EntryReaderRepoStruct{db: db}
}
func (r *EntryReaderRepoStruct) Get(ctx context.Context, id uuid.UUID) (*models.Entry, error) {
	return scanEntry(r.db.QueryRow(ctx, `SELECT `+entryColumns+` FROM audit_entries WHERE id=$1`, id))
}
func (r *EntryReaderRepoStruct) List(ctx context.Context, f models.Filter) ([]*models.Entry, int64, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := r.db.Query(ctx, `SELECT `+entryColumns+`,count(*) OVER() FROM audit_entries WHERE ($1::uuid IS NULL OR actor_id=$1) AND ($2::text IS NULL OR action=$2) AND ($3::text IS NULL OR entity_type=$3) AND ($4::text IS NULL OR entity_id=$4) AND ($5::text IS NULL OR request_id=$5) AND ($6::text IS NULL OR trace_id=$6) AND ($7::text IS NULL OR topic=$7) AND ($8::timestamptz IS NULL OR occurred_at >= $8) AND ($9::timestamptz IS NULL OR occurred_at <= $9) ORDER BY occurred_at DESC,id DESC LIMIT $10 OFFSET $11`, f.ActorID, f.Action, f.EntityType, f.EntityID, f.RequestID, f.TraceID, f.Topic, f.From, f.To, limit, max(f.Offset, 0))
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]*models.Entry, 0)
	var total int64
	for rows.Next() {
		entry, e := scanEntryWithTotal(rows, &total)
		if e != nil {
			return nil, 0, e
		}
		items = append(items, entry)
	}
	return items, total, rows.Err()
}
