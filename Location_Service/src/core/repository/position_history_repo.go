package repository

import (
	"context"
	"errors"
	"fmt"

	"location/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PositionHistoryRepoStruct struct {
	writePool *pgxpool.Pool
	readPool  *pgxpool.Pool
}

func NewPositionHistoryRepo(writePool, readPool *pgxpool.Pool) *PositionHistoryRepoStruct {
	if readPool == nil {
		readPool = writePool
	}
	return &PositionHistoryRepoStruct{writePool: writePool, readPool: readPool}
}

func (r *PositionHistoryRepoStruct) AppendPositionsBatch(
	ctx context.Context,
	positions []*models.Position,
) (int64, error) {
	if len(positions) == 0 {
		return 0, nil
	}
	rows := make([][]any, 0, len(positions))
	for _, position := range positions {
		if position == nil {
			return 0, fmt.Errorf(
				"repository: AppendPositionsBatch: %w: nil position",
				models.ErrValidation,
			)
		}
		if position.ID == uuid.Nil {
			position.ID = uuid.New()
		}
		rows = append(
			rows,
			[]any{
				position.ID,
				position.EventID,
				position.DeviceID,
				position.VehicleID,
				position.BrigadeID,
				int64(
					position.Sequence,
				),
				position.Latitude,
				position.Longitude,
				position.SpeedKMH,
				position.Heading,
				position.AccuracyMeters,
				position.AltitudeMeters,
				position.Simulated,
				position.RecordedAt,
				position.ReceivedAt,
			},
		)
	}
	count, err := r.writePool.CopyFrom(ctx, pgx.Identifier{"position_history"}, []string{
		"id", "event_id", "device_id", "vehicle_id", "brigade_id", "sequence", "latitude", "longitude",
		"speed_kmh", "heading", "accuracy_meters", "altitude_meters", "simulated", "recorded_at", "received_at",
	}, pgx.CopyFromRows(rows))
	if err != nil {
		return count, fmt.Errorf("repository: AppendPositionsBatch: %w", err)
	}
	return count, nil
}

func (r *PositionHistoryRepoStruct) ListPositionHistory(
	ctx context.Context,
	in *models.ListPositionHistoryInput,
) (*models.ListPositionHistoryResult, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = models.DefaultLimit
	}
	order := "DESC"
	if in.Order == models.SortOrderAsc {
		order = "ASC"
	}
	query := `SELECT id,event_id,device_id,vehicle_id,brigade_id,sequence,latitude,longitude,speed_kmh,heading,
		accuracy_meters,altitude_meters,simulated,recorded_at,received_at
		FROM position_history WHERE brigade_id=$1 AND recorded_at >= $2 AND recorded_at < $3
		ORDER BY recorded_at ` + order + `, sequence ` + order + ` LIMIT $4 OFFSET $5`
	rows, err := r.readPool.Query(ctx, query, in.BrigadeID, in.From, in.To, limit, in.Offset)
	if err != nil {
		return nil, fmt.Errorf("repository: ListPositionHistory: query: %w", err)
	}
	defer rows.Close()
	result := &models.ListPositionHistoryResult{Positions: make([]*models.Position, 0, limit)}
	for rows.Next() {
		position := new(models.Position)
		var sequence int64
		if err = rows.Scan(
			&position.ID,
			&position.EventID,
			&position.DeviceID,
			&position.VehicleID,
			&position.BrigadeID,
			&sequence,
			&position.Latitude,
			&position.Longitude,
			&position.SpeedKMH,
			&position.Heading,
			&position.AccuracyMeters,
			&position.AltitudeMeters,
			&position.Simulated,
			&position.RecordedAt,
			&position.ReceivedAt,
		); err != nil {
			return nil, fmt.Errorf("repository: ListPositionHistory: scan: %w", err)
		}
		position.Sequence = uint64(sequence)
		result.Positions = append(result.Positions, position)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("repository: ListPositionHistory: rows: %w", err)
	}
	const countQuery = `SELECT count(*)
		FROM position_history
		WHERE brigade_id = $1 AND recorded_at >= $2 AND recorded_at < $3`

	if err = r.readPool.QueryRow(
		ctx,
		countQuery,
		in.BrigadeID,
		in.From,
		in.To,
	).Scan(&result.Total); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("repository: ListPositionHistory: count: %w", err)
	}
	return result, nil
}
