package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"asset/models"
	"asset/src/core/repository"
)

type assetStore struct {
	repository.AssetRepository
	err, factsErr, saveErr error
	asset                  *models.Asset
	filter                 models.Filter
	limit                  int32
	writes                 int
	ids                    []uuid.UUID
	factsCalls             int
}

func (r *assetStore) Create(context.Context, models.CreateInput) (*models.Asset, error) {
	r.writes++
	return r.asset, r.err
}
func (r *assetStore) Update(context.Context, models.UpdateInput) (*models.Asset, error) {
	r.writes++
	return r.asset, r.err
}
func (r *assetStore) Get(context.Context, uuid.UUID) (*models.Asset, error) { return r.asset, r.err }
func (r *assetStore) List(_ context.Context, f models.Filter) ([]*models.Asset, int64, error) {
	r.filter = f
	return []*models.Asset{r.asset}, 8, r.err
}
func (r *assetStore) ChangeStatus(context.Context, uuid.UUID, models.Status, uuid.UUID, string) (*models.Asset, error) {
	r.writes++
	return r.asset, r.err
}
func (r *assetStore) Nearby(_ context.Context, _, _, _ float64, _ *string, l int32) ([]*models.Asset, error) {
	r.limit = l
	return []*models.Asset{r.asset}, r.err
}
func (r *assetStore) RecordIncident(_ context.Context, v models.Incident) (*models.Incident, error) {
	r.writes++
	return &v, r.err
}
func (r *assetStore) CompleteRepair(_ context.Context, v models.Repair) (*models.Repair, error) {
	r.writes++
	return &v, r.err
}
func (r *assetStore) RecordInspection(_ context.Context, v models.Inspection) (*models.Inspection, error) {
	r.writes++
	return &v, r.err
}
func (r *assetStore) CreatePlan(_ context.Context, v models.Plan) (*models.Plan, error) {
	r.writes++
	return &v, r.err
}
func (r *assetStore) DuePlans(_ context.Context, _ *uuid.UUID, _ time.Time, l, _ int32) ([]*models.Plan, int64, error) {
	r.limit = l
	return nil, 8, r.err
}
func (r *assetStore) GetPrediction(context.Context, uuid.UUID) (*models.Prediction, error) {
	return &models.Prediction{Score: 42}, r.err
}
func (r *assetStore) ListIDs(context.Context, *uuid.UUID) ([]uuid.UUID, error) { return r.ids, r.err }
func (r *assetStore) RiskFacts(context.Context, uuid.UUID, time.Time) (repository.RiskFacts, error) {
	r.factsCalls++
	return repository.RiskFacts{}, r.factsErr
}
func (r *assetStore) SavePrediction(context.Context, models.Prediction) error {
	r.writes++
	return r.saveErr
}

func TestAssetWritePermissions(t *testing.T) {
	t.Parallel()
	r := &assetStore{}
	s := &AssetServiceStruct{repo: r}
	ctx := context.Background()
	operations := []struct {
		name string
		call func() error
	}{
		{"create", func() error { _, e := s.Create(ctx, models.CreateInput{}, false); return e }},
		{"update", func() error { _, e := s.Update(ctx, models.UpdateInput{}, false); return e }},
		{"status", func() error {
			_, e := s.ChangeStatus(ctx, uuid.New(), models.StatusActive, uuid.New(), "", false)
			return e
		}},
		{"incident", func() error { _, _, e := s.Incident(ctx, models.Incident{}, false); return e }},
		{"repair", func() error { _, _, e := s.Repair(ctx, models.Repair{}, false); return e }},
		{"inspection", func() error { _, _, e := s.Inspection(ctx, models.Inspection{}, false); return e }},
		{"plan", func() error { _, e := s.CreatePlan(ctx, models.Plan{}, false); return e }},
		{"recalculate", func() error { _, e := s.Recalculate(ctx, nil, false); return e }},
	}
	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			if err := op.call(); !errors.Is(err, models.ErrForbidden) || r.writes != 0 || r.factsCalls != 0 {
				t.Fatalf("%s(forbidden) = %v, writes=%d calculations=%d", op.name, err, r.writes, r.factsCalls)
			}
		})
	}
}
func TestAssetCreateValidation(t *testing.T) {
	t.Parallel()
	valid := models.CreateInput{Asset: models.Asset{DepartmentID: uuid.New(), Name: "pump", Type: "pump", Geometry: "POINT(0 0)", Criticality: .5}}
	future := int32(time.Now().UTC().Year() + 1)
	for _, tt := range []struct {
		name   string
		change func(*models.CreateInput)
	}{
		{"department", func(v *models.CreateInput) { v.DepartmentID = uuid.Nil }},
		{"name", func(v *models.CreateInput) { v.Name = "" }},
		{"type", func(v *models.CreateInput) { v.Type = "" }},
		{"geometry", func(v *models.CreateInput) { v.Geometry = "" }},
		{"negative criticality", func(v *models.CreateInput) { v.Criticality = -.1 }},
		{"criticality above one", func(v *models.CreateInput) { v.Criticality = 1.1 }},
		{"future installation", func(v *models.CreateInput) { v.InstallationYear = &future }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &assetStore{}
			v := valid
			tt.change(&v)
			if _, err := (&AssetServiceStruct{repo: r}).Create(context.Background(), v, true); err == nil || r.writes != 0 {
				t.Fatalf("Create(%+v) = %v, writes=%d; want rejection without write", v, err, r.writes)
			}
		})
	}
	r := &assetStore{asset: &models.Asset{ID: uuid.New()}}
	s := &AssetServiceStruct{repo: r}
	for _, wantErr := range []error{nil, context.Canceled} {
		r.err = wantErr
		got, err := s.Create(context.Background(), valid, true)
		if got != r.asset || !errors.Is(err, wantErr) {
			t.Fatalf("Create(valid) = %v, %v; want asset, %v", got, err, wantErr)
		}
	}
}
func TestAssetUpdatesAndQueries(t *testing.T) {
	t.Parallel()
	r := &assetStore{asset: &models.Asset{ID: uuid.New()}}
	s := &AssetServiceStruct{repo: r}
	ctx := context.Background()
	bad := 1.1
	if _, err := s.Update(ctx, models.UpdateInput{Criticality: &bad}, true); err == nil || r.writes != 0 {
		t.Fatalf("Update(invalid criticality) = %v, writes=%d", err, r.writes)
	}
	if got, err := s.Update(ctx, models.UpdateInput{ID: r.asset.ID}, true); got != r.asset || err != nil {
		t.Fatalf("Update = %v, %v", got, err)
	}
	if got, err := s.Get(ctx, r.asset.ID); got != r.asset || err != nil {
		t.Fatalf("Get = %v, %v", got, err)
	}
	if got, err := s.ChangeStatus(ctx, r.asset.ID, models.StatusActive, uuid.New(), "repaired", true); got != r.asset || err != nil {
		t.Fatalf("ChangeStatus = %v, %v", got, err)
	}
	for _, tt := range []struct{ input, want int32 }{{0, 20}, {200, 100}, {10, 10}} {
		_, total, err := s.List(ctx, models.Filter{Limit: tt.input, Offset: 3})
		if err != nil || total != 8 || r.filter.Limit != tt.want || r.filter.Offset != 3 {
			t.Fatalf("List(%d) filter=%+v total=%d err=%v", tt.input, r.filter, total, err)
		}
	}
	for _, tt := range []struct{ lat, lon, radius float64 }{{-91, 0, 1}, {91, 0, 1}, {0, -181, 1}, {0, 181, 1}, {0, 0, 0}} {
		if _, err := s.Nearby(ctx, tt.lat, tt.lon, tt.radius, nil, 20); err == nil {
			t.Fatalf("Nearby(%+v) accepted invalid coordinates", tt)
		}
	}
	for _, tt := range []struct{ input, want int32 }{{0, 20}, {101, 20}, {10, 10}} {
		if _, err := s.Nearby(ctx, 55, 37, 100, nil, tt.input); err != nil || r.limit != tt.want {
			t.Fatalf("Nearby(limit=%d) = %v limit=%d; want %d", tt.input, err, r.limit, tt.want)
		}
	}
	if _, err := s.CreatePlan(ctx, models.Plan{}, true); err == nil {
		t.Fatal("CreatePlan accepted zero interval")
	}
	if _, err := s.CreatePlan(ctx, models.Plan{IntervalDays: 30}, true); err != nil {
		t.Fatalf("CreatePlan = %v", err)
	}
	for _, limit := range []int32{0, 10} {
		_, total, err := s.Due(ctx, nil, time.Now(), limit, 3)
		want := limit
		if want == 0 {
			want = 20
		}
		if err != nil || total != 8 || r.limit != want {
			t.Fatalf("Due(%d) = %d, %v; limit=%d", limit, total, err, r.limit)
		}
	}
}
func TestMaintenanceRecalculatesAfterSuccessfulWrite(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"incident", "repair", "inspection"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			for _, tt := range []struct {
				name                        string
				writeErr, factsErr, saveErr error
				wantFacts                   int
				wantResult                  bool
			}{
				{name: "success", wantFacts: 1, wantResult: true},
				{name: "write fails", writeErr: context.Canceled},
				{name: "risk facts fail after commit", factsErr: context.Canceled, wantFacts: 1, wantResult: true},
				{name: "prediction save fails after commit", saveErr: context.Canceled, wantFacts: 1, wantResult: true},
			} {
				t.Run(tt.name, func(t *testing.T) {
					r := &assetStore{err: tt.writeErr, factsErr: tt.factsErr, saveErr: tt.saveErr}
					s := &AssetServiceStruct{repo: r}
					id := uuid.New()
					ctx := context.Background()
					var result bool
					var err error
					switch operation {
					case "incident":
						v, _, e := s.Incident(ctx, models.Incident{AssetID: id}, true)
						result = v != nil
						err = e
					case "repair":
						v, _, e := s.Repair(ctx, models.Repair{AssetID: id}, true)
						result = v != nil
						err = e
					case "inspection":
						v, _, e := s.Inspection(ctx, models.Inspection{AssetID: id, ConditionScore: .8}, true)
						result = v != nil
						err = e
					}
					wantErr := tt.writeErr
					if wantErr == nil {
						wantErr = tt.factsErr
					}
					if wantErr == nil {
						wantErr = tt.saveErr
					}
					if !errors.Is(err, wantErr) || result != tt.wantResult || r.factsCalls != tt.wantFacts {
						t.Fatalf("%s = result %v err %v calculations %d; want %v %v %d", operation, result, err, r.factsCalls, tt.wantResult, wantErr, tt.wantFacts)
					}
				})
			}
		})
	}
	r := &assetStore{}
	s := &AssetServiceStruct{repo: r}
	for _, score := range []float64{-.1, 1.1} {
		if _, _, err := s.Inspection(context.Background(), models.Inspection{ConditionScore: score}, true); err == nil || r.writes != 0 {
			t.Fatalf("Inspection(%v) = %v writes=%d", score, err, r.writes)
		}
	}
}
func TestPredictionAndRecalculateFailures(t *testing.T) {
	t.Parallel()
	r := &assetStore{}
	s := &AssetServiceStruct{repo: r}
	ctx := context.Background()
	id := uuid.New()
	if p, err := s.Prediction(ctx, id); err != nil || p.Score != 42 || r.factsCalls != 0 {
		t.Fatalf("Prediction(cached) = %v, %v", p, err)
	}
	r.err = pgx.ErrNoRows
	if _, err := s.Prediction(ctx, id); err != nil || r.factsCalls != 1 {
		t.Fatalf("Prediction(missing) = %v calculations=%d", err, r.factsCalls)
	}
	r.err = context.Canceled
	if _, err := s.Prediction(ctx, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("Prediction(storage error) = %v", err)
	}
	if n, err := s.Recalculate(ctx, nil, true); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("Recalculate(list failure) = %d, %v", n, err)
	}
	r.err = nil
	r.ids = []uuid.UUID{id, uuid.New()}
	r.factsCalls = 0
	r.factsErr = context.Canceled
	if n, err := s.Recalculate(ctx, nil, true); n != 0 || !errors.Is(err, context.Canceled) || r.factsCalls != 1 {
		t.Fatalf("Recalculate(facts failure) = %d, %v calculations=%d", n, err, r.factsCalls)
	}
	r.factsErr = nil
	if n, err := s.Recalculate(ctx, nil, true); n != 2 || err != nil {
		t.Fatalf("Recalculate(success) = %d, %v", n, err)
	}
}
