package service

import (
	"context"
	"testing"

	"analytics/models"
	"analytics/src/core/repository"
)

type fakeRepository struct {
	stored bool
	event  models.Event
}

func (f *fakeRepository) Store(_ context.Context, event models.Event) error {
	f.stored = true
	f.event = event
	return nil
}
func (*fakeRepository) Overview(context.Context, models.Filter) (models.Overview, error) {
	return models.Overview{Created: 7}, nil
}

func TestConsumeStoresUnknownVersionWithoutProjection(t *testing.T) {
	writer := new(fakeRepository)
	repo := &repository.Repository{EventRepository: writer}
	svc := NewService(repo, nil)
	if err := svc.Consume(context.Background(), models.Event{Topic: "dispatch.events.v1", Type: "dispatch.failed", Version: 7}); err != nil {
		t.Fatalf("Consume(version=7) error = %v", err)
	}
	if !writer.stored || writer.event.Version != 7 || writer.event.ProjectionEligible {
		t.Errorf("Consume(version=7) stored event = %+v, want stored and projection ineligible", writer.event)
	}
}
func (*fakeRepository) SLA(context.Context, models.Filter) (models.SLA, error) {
	return models.SLA{ResponseBreaches: 2}, nil
}
func (*fakeRepository) Breakdown(context.Context, models.Filter, string, int32) ([]models.Breakdown, uint64, error) {
	return []models.Breakdown{{Key: "HIGH", Count: 3}}, 3, nil
}
func (*fakeRepository) Daily(context.Context, models.Filter) ([]models.Daily, error) {
	return []models.Daily{{Created: 1}}, nil
}
func (*fakeRepository) OperationalLatency(context.Context, models.Filter, string) (models.OperationalLatency, error) {
	return models.OperationalLatency{
		AssignmentTime: models.LatencyDistribution{SampleCount: 4},
	}, nil
}
func (*fakeRepository) DispatchFailures(context.Context, models.Filter) (models.DispatchFailureSummary, error) {
	return models.DispatchFailureSummary{Requested: 5, Failed: 2, FailureRate: 40}, nil
}
func (*fakeRepository) BrigadeWorkload(context.Context, models.Filter) (models.BrigadeWorkload, error) {
	return models.BrigadeWorkload{Active: 3, Brigades: []models.BrigadeWorkloadItem{{BrigadeID: "brigade-1", Active: 3}}}, nil
}
func (*fakeRepository) ActiveWorkers(context.Context, models.Filter) (models.ActiveWorkers, error) {
	return models.ActiveWorkers{ActiveMembers: 8, Available: 5}, nil
}
func (*fakeRepository) AssignmentFunnel(context.Context, models.Filter) (models.AssignmentFunnel, error) {
	return models.AssignmentFunnel{Stages: []models.AssignmentFunnelStage{{Stage: "REQUESTED", Count: 10}}}, nil
}
func (*fakeRepository) DispatchEffectiveness(context.Context, models.Filter) (models.DispatchEffectiveness, error) {
	return models.DispatchEffectiveness{Automatic: models.DispatchModeEffectiveness{Requested: 5, Assigned: 4, SuccessRate: 80}}, nil
}
func (*fakeRepository) OperationalInsights(context.Context, models.Filter) (models.OperationalInsights, error) {
	return models.OperationalInsights{QueueAge: models.QueueAgeSummary{ActiveUnassigned: 6}}, nil
}
func (*fakeRepository) ProjectionHealth(context.Context) (models.ProjectionHealth, error) {
	return models.ProjectionHealth{TotalEvents: 10, UnknownVersionEvents: 1}, nil
}
func (*fakeRepository) DispatchOperations(context.Context, models.Filter, uint32) ([]models.DispatchOperationItem, error) {
	return []models.DispatchOperationItem{{OperationID: "operation-1"}}, nil
}
func (*fakeRepository) BrigadePerformance(context.Context, models.Filter) (models.BrigadePerformance, error) {
	return models.BrigadePerformance{Completed: 4}, nil
}

func TestServiceUsesPorts(t *testing.T) {
	repo := &repository.Repository{
		EventRepository:                 new(fakeRepository),
		OverviewRepository:              new(fakeRepository),
		SLARepository:                   new(fakeRepository),
		BreakdownRepository:             new(fakeRepository),
		DailyRepository:                 new(fakeRepository),
		OperationalLatencyRepository:    new(fakeRepository),
		DispatchFailureRepository:       new(fakeRepository),
		BrigadeWorkloadRepository:       new(fakeRepository),
		ActiveWorkersRepository:         new(fakeRepository),
		AssignmentFunnelRepository:      new(fakeRepository),
		DispatchEffectivenessRepository: new(fakeRepository),
		OperationalInsightsRepository:   new(fakeRepository),
		ProjectionHealthRepository:      new(fakeRepository),
		DispatchOperationsRepository:    new(fakeRepository),
		BrigadePerformanceRepository:    new(fakeRepository),
	}
	svc := NewService(repo, nil)
	if err := svc.Consume(context.Background(), models.Event{}); err != nil || !repo.EventRepository.(*fakeRepository).stored {
		t.Fatal("writer was not used")
	}
	v, err := svc.Overview(context.Background(), models.Filter{})
	if err != nil || v.Created != 7 {
		t.Fatal("reader was not used")
	}
	latency, err := svc.OperationalLatency(context.Background(), models.Filter{}, "")
	if err != nil || latency.AssignmentTime.SampleCount != 4 {
		t.Fatalf("OperationalLatency() = (%+v, %v), want assignment sample count 4", latency, err)
	}
	failures, err := svc.DispatchFailures(context.Background(), models.Filter{})
	if err != nil || failures.Requested != 5 || failures.Failed != 2 || failures.FailureRate != 40 {
		t.Fatalf("DispatchFailures() = (%+v, %v), want 2/5 failures", failures, err)
	}
	workload, err := svc.BrigadeWorkload(context.Background(), models.Filter{})
	if err != nil || workload.Active != 3 || len(workload.Brigades) != 1 {
		t.Fatalf("BrigadeWorkload() = (%+v, %v), want one brigade with three active tickets", workload, err)
	}
	workers, err := svc.ActiveWorkers(context.Background(), models.Filter{})
	if err != nil || workers.ActiveMembers != 8 || workers.Available != 5 {
		t.Fatalf("ActiveWorkers() = (%+v, %v), want 5/8 available", workers, err)
	}
	funnel, err := svc.AssignmentFunnel(context.Background(), models.Filter{})
	if err != nil || len(funnel.Stages) != 1 || funnel.Stages[0].Count != 10 {
		t.Fatalf("AssignmentFunnel() = (%+v, %v), want ten requested operations", funnel, err)
	}
	effectiveness, err := svc.DispatchEffectiveness(context.Background(), models.Filter{})
	if err != nil || effectiveness.Automatic.Requested != 5 || effectiveness.Automatic.Assigned != 4 || effectiveness.Automatic.SuccessRate != 80 {
		t.Fatalf("DispatchEffectiveness() = (%+v, %v), want 4/5 automatic assignments", effectiveness, err)
	}
	insights, err := svc.OperationalInsights(context.Background(), models.Filter{})
	if err != nil || insights.QueueAge.ActiveUnassigned != 6 {
		t.Fatalf("OperationalInsights() = (%+v, %v), want queue size 6", insights, err)
	}
	health, err := svc.ProjectionHealth(context.Background())
	if err != nil || health.TotalEvents != 10 || health.UnknownVersionEvents != 1 {
		t.Fatalf("ProjectionHealth() = (%+v, %v), want 1 unknown of 10", health, err)
	}
	operations, err := svc.DispatchOperations(context.Background(), models.Filter{}, 10)
	if err != nil || len(operations) != 1 || operations[0].OperationID != "operation-1" {
		t.Fatalf("DispatchOperations() = (%+v, %v), want operation-1", operations, err)
	}
	performance, err := svc.BrigadePerformance(context.Background(), models.Filter{})
	if err != nil || performance.Completed != 4 {
		t.Fatalf("BrigadePerformance() = (%+v, %v), want 4 completed", performance, err)
	}
}
