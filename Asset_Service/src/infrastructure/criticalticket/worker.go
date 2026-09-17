package criticalticket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	ticketv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/ticket/v1"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

const eventTypeRiskBecameCritical = "asset.RISK_BECAME_CRITICAL"

type Config struct {
	Brokers        []string
	Topic          string
	GroupID        string
	CategoryID     string
	RequesterID    string
	ActorRoles     string
	RequestTimeout time.Duration
}

type Worker struct {
	reader *kafka.Reader
	ticket ticketv1.TicketServiceClient
	config Config
	logger *zap.Logger
}

type eventEnvelope struct {
	EventID   string              `json:"event_id"`
	EventType string              `json:"event_type"`
	Data      criticalRiskPayload `json:"data"`
}

type criticalRiskPayload struct {
	AssetID      string     `json:"asset_id"`
	DepartmentID string     `json:"department_id"`
	Name         string     `json:"name"`
	Type         string     `json:"type"`
	Address      string     `json:"address"`
	Latitude     float64    `json:"latitude"`
	Longitude    float64    `json:"longitude"`
	Prediction   prediction `json:"prediction"`
}

type prediction struct {
	Score       float64  `json:"Score"`
	Probability float64  `json:"Probability"`
	Level       string   `json:"Level"`
	Factors     []string `json:"Factors"`
	Action      string   `json:"Action"`
}

func New(config Config, ticket ticketv1.TicketServiceClient, logger *zap.Logger) (*Worker, error) {
	if len(config.Brokers) == 0 || config.Topic == "" || config.GroupID == "" {
		return nil, errors.New("critical ticket worker: brokers, topic and group id are required")
	}
	if config.CategoryID == "" || config.RequesterID == "" {
		return nil, errors.New("critical ticket worker: category id and requester id are required")
	}
	if ticket == nil {
		return nil, errors.New("critical ticket worker: ticket client is required")
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 5 * time.Second
	}
	if config.ActorRoles == "" {
		config.ActorRoles = "dispatcher"
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: config.Brokers,
		Topic:   config.Topic,
		GroupID: config.GroupID,
	})

	return &Worker{
		reader: reader,
		ticket: ticket,
		config: config,
		logger: logger,
	}, nil
}

func (w *Worker) Close() error {
	return w.reader.Close()
}

func (w *Worker) Run(ctx context.Context) error {
	for {
		message, err := w.reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			w.logger.Warn("fetch critical risk event failed", zap.Error(err))
			continue
		}

		if err = w.apply(ctx, message); err != nil {
			w.logger.Warn("critical risk event processing failed", zap.Int64("offset", message.Offset), zap.Error(err))
			continue
		}
		if err = w.reader.CommitMessages(ctx, message); err != nil {
			return fmt.Errorf("commit critical risk event: %w", err)
		}
	}
}

func (w *Worker) apply(ctx context.Context, message kafka.Message) error {
	var event eventEnvelope
	if err := json.Unmarshal(message.Value, &event); err != nil {
		return fmt.Errorf("decode critical risk event: %w", err)
	}
	if event.EventType != eventTypeRiskBecameCritical {
		return nil
	}
	if event.EventID == "" {
		return errors.New("critical risk event id is required")
	}
	if _, err := uuid.Parse(event.Data.AssetID); err != nil {
		return fmt.Errorf("invalid asset_id: %w", err)
	}

	requestCtx, cancel := context.WithTimeout(ctx, w.config.RequestTimeout)
	defer cancel()

	requestCtx = metadata.AppendToOutgoingContext(
		requestCtx,
		"x-actor-user-id", w.config.RequesterID,
		"x-actor-roles", w.config.ActorRoles,
		"x-idempotency-key", "asset-critical-risk:"+event.EventID,
	)

	_, err := w.ticket.CreateTicket(requestCtx, &ticketv1.CreateTicketRequest{
		DepartmentId: event.Data.DepartmentID,
		CategoryId:   w.config.CategoryID,
		UserId:       w.config.RequesterID,
		Title:        title(event.Data),
		Description:  description(event.Data),
		Priority:     ticketv1.TicketPriority_TICKET_PRIORITY_HIGH,
		Address:      event.Data.Address,
		Latitude:     &event.Data.Latitude,
		Longitude:    &event.Data.Longitude,
		AssetId:      &event.Data.AssetID,
	})
	if err != nil {
		return fmt.Errorf("create critical risk ticket: %w", err)
	}

	w.logger.Info("critical risk ticket requested", zap.String("asset_id", event.Data.AssetID), zap.String("event_id", event.EventID))
	return nil
}

func title(payload criticalRiskPayload) string {
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		name = payload.AssetID
	}
	return limitText("Critical failure risk: "+name, 255)
}

func description(payload criticalRiskPayload) string {
	factors := strings.Join(payload.Prediction.Factors, "; ")
	if factors == "" {
		factors = "no detailed factors"
	}
	text := fmt.Sprintf(
		"Asset %s reached CRITICAL failure risk. Score: %.1f, probability 90d: %.1f%%. Recommended action: %s. Factors: %s.",
		payload.AssetID,
		payload.Prediction.Score,
		payload.Prediction.Probability,
		payload.Prediction.Action,
		factors,
	)
	return limitText(text, 3000)
}

func limitText(text string, max int) string {
	if len(text) <= max {
		return text
	}
	if max <= 3 {
		return text[:max]
	}
	return text[:max-3] + "..."
}
