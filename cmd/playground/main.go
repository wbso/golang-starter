package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/sanity-io/litter"
	"github.com/wbso/golang-starter/internal/pkg/jwt"
)

func run(ctx context.Context) error {
	v, err := jwt.NewVerifier(ctx, jwt.Config{
		JwksURL:   []string{"https://sso.bantulkab.go.id/auth/realms/passkeyku/protocol/openid-connect/certs"},
		Issuer:    "https://sso.bantulkab.go.id/auth/realms/passkeyku",
		Audiences: []string{"account"},
	})
	if err != nil {
		return err
	}

	tok, err := v.Verify(ctx, "eyJhbGciOiJFZERTQSIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJBLTZFb2lVMGI3UmZhVmx5Z3BIVV94bFllV3o2RnE4a3ZOOXI1c3pPX1MwIn0.eyJleHAiOjE3Njc3MjEzNDgsImlhdCI6MTc2NzcyMTA0OCwianRpIjoib25ydHJvOjJmZGE1M2ExLWIwMTYtNDRlYi1lYzhiLTMxMGRhYTMwYTRjZCIsImlzcyI6Imh0dHBzOi8vc3NvLmJhbnR1bGthYi5nby5pZC9hdXRoL3JlYWxtcy9wYXNza2V5a3UiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiYmY4NTE5ZTAtNDg2My00ZWQxLTgwY2UtZTMxZDIzODAxNTc3IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoicG9zdG1hbiIsInNpZCI6ImI1MTM3M2UyLTU0OTgtMTE1Yi1kOTY4LTYwOTc1MTU0MTY0YyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtcGFzc2tleWt1Iiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlVzZXIwMSBVc2VyMDEiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1c2VyMDEiLCJnaXZlbl9uYW1lIjoiVXNlcjAxIiwiZmFtaWx5X25hbWUiOiJVc2VyMDEiLCJlbWFpbCI6InVzZXIwMUBleGFtcGxlLmNvbSJ9.1GZtMZw2Oz1BzhkF-bmGpJPD7-HPuzDpxo5wURWjWaGToHay44PLpTeARm11qUPLL4Gl1_I3xTgbxdBN40FJDA")
	if err != nil {
		return err
	}

	litter.Dump(tok)

	return nil
}

func main() {
	err := run(context.Background())
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}
