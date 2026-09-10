package main

import (
	"context"
	"fmt"
	"os"
	"time"

	slav1 "github.com/FIZZI-77/automatic-system-contracts/gen/go/sla/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(address(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	check(err)
	defer conn.Close()
	client := slav1.NewSLAServiceClient(conn)
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-actor-roles", "admin"))
	created, err := client.CreateRule(ctx, &slav1.CreateRuleRequest{Name: "smoke rule " + time.Now().Format(time.RFC3339Nano), ResponseTimeSeconds: 60, ResolutionTimeSeconds: 300, WarningPercent: 80})
	check(err)
	got, err := client.GetRule(ctx, &slav1.GetRuleRequest{Id: created.GetRule().GetId()})
	check(err)
	listed, err := client.ListRules(ctx, &slav1.ListRulesRequest{Limit: 100})
	check(err)
	_, err = client.DeleteRule(ctx, &slav1.DeleteRuleRequest{Id: created.GetRule().GetId()})
	check(err)
	fmt.Printf("rule=%s name=%q total=%d\n", got.GetRule().GetId(), got.GetRule().GetName(), listed.GetTotal())
}

func address() string {
	if v := os.Getenv("SLA_ADDR"); v != "" {
		return v
	}
	return "localhost:50060"
}
func check(err error) {
	if err != nil {
		panic(err)
	}
}
