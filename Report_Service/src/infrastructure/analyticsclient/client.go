package analyticsclient

import (
	"context"
	"fmt"
	analyticsv1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/analytics/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	"report/models"
	"strings"
)

type Client struct {
	api analyticsv1.AnalyticsServiceClient
}

func New(api analyticsv1.AnalyticsServiceClient) *Client { return &Client{api: api} }
func (c *Client) Build(ctx context.Context, t models.Type, f models.Filter, roles []string) ([][]string, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-actor-roles", strings.Join(roles, ","))
	filter := protoFilter(f)
	switch t {
	case models.TypeTicketOverview:
		x, e := c.api.GetTicketOverview(ctx, &analyticsv1.GetTicketOverviewRequest{Filter: filter})
		if e != nil {
			return nil, e
		}
		return [][]string{{"Metric", "Value"}, {"Created", fmt.Sprint(x.Created)}, {"Completed", fmt.Sprint(x.Completed)}, {"Canceled", fmt.Sprint(x.Canceled)}, {"Active", fmt.Sprint(x.Active)}, {"Completion rate", fmt.Sprintf("%.2f%%", x.CompletionRate)}, {"Average response (sec)", fmt.Sprintf("%.2f", x.AvgResponseSeconds)}, {"Average resolution (sec)", fmt.Sprintf("%.2f", x.AvgResolutionSeconds)}}, nil
	case models.TypeSLASummary:
		x, e := c.api.GetSLASummary(ctx, &analyticsv1.GetSLASummaryRequest{Filter: filter})
		if e != nil {
			return nil, e
		}
		return [][]string{{"Metric", "Value"}, {"Response warnings", fmt.Sprint(x.ResponseWarnings)}, {"Response breaches", fmt.Sprint(x.ResponseBreaches)}, {"Resolution warnings", fmt.Sprint(x.ResolutionWarnings)}, {"Resolution breaches", fmt.Sprint(x.ResolutionBreaches)}, {"Completed", fmt.Sprint(x.Completed)}, {"Breach rate", fmt.Sprintf("%.2f%%", x.BreachRate)}}, nil
	case models.TypeTicketBreakdown:
		x, e := c.api.ListTicketBreakdown(ctx, &analyticsv1.ListTicketBreakdownRequest{Filter: filter, Dimension: analyticsv1.BreakdownDimension_BREAKDOWN_DIMENSION_DEPARTMENT, Limit: 100})
		if e != nil {
			return nil, e
		}
		rows := [][]string{{"Department", "Count", "Percent"}}
		for _, v := range x.Items {
			rows = append(rows, []string{v.Key, fmt.Sprint(v.Count), fmt.Sprintf("%.2f%%", v.Percent)})
		}
		return rows, nil
	case models.TypeDailyTickets:
		x, e := c.api.ListDailyTicketMetrics(ctx, &analyticsv1.ListDailyTicketMetricsRequest{Filter: filter})
		if e != nil {
			return nil, e
		}
		rows := [][]string{{"Day", "Created", "Completed", "Canceled", "SLA breaches"}}
		for _, v := range x.Items {
			rows = append(rows, []string{v.Day.AsTime().Format("2006-01-02"), fmt.Sprint(v.Created), fmt.Sprint(v.Completed), fmt.Sprint(v.Canceled), fmt.Sprint(v.SlaBreaches)})
		}
		return rows, nil
	}
	return nil, fmt.Errorf("unsupported report type %s", t)
}
func protoFilter(f models.Filter) *analyticsv1.AnalyticsFilter {
	x := &analyticsv1.AnalyticsFilter{DepartmentId: f.DepartmentID, CategoryId: f.CategoryID, Priority: f.Priority}
	if f.From != nil {
		x.From = timestamppb.New(*f.From)
	}
	if f.To != nil {
		x.To = timestamppb.New(*f.To)
	}
	return x
}
