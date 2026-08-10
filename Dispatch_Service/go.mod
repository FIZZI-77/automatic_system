module dispatch

go 1.25.9

replace github.com/FIZZI-77/automatic-system-contracts => ../../contracts

require (
	github.com/FIZZI-77/automatic-system-contracts v0.0.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.9.2
	go.uber.org/zap v1.28.0
	google.golang.org/grpc v1.81.1
)
