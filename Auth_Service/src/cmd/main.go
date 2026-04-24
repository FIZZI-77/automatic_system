package main

import (
	authv1 "auth/auth/v1"
	"auth/src/core/handler"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {

	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	authHandler := handler.NewAuthHandler()
	authv1.RegisterAuthServiceServer(grpcServer, authHandler)

	log.Printf("server listening at %v", lis.Addr())

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
