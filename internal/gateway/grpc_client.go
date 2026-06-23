package gateway

import (
	"context"
	"io"
	"strings"

	captchav1 "captcha/gen/captcha/v1"
	"captcha/internal/grpccontract"
	"captcha/internal/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type GRPCPolicyClient struct {
	conn         grpc.ClientConnInterface
	clientSecret string
	grpcToken    string
}

type GRPCTicketClient struct {
	conn         grpc.ClientConnInterface
	clientSecret string
	grpcToken    string
}

type GRPCEventClient struct {
	conn         grpc.ClientConnInterface
	clientSecret string
	grpcToken    string
}

type GRPCConfigClient struct {
	conn         grpc.ClientConnInterface
	clientSecret string
	grpcToken    string
}

func NewGRPCPolicyClient(target string) (*GRPCPolicyClient, error) {
	return NewGRPCPolicyClientWithSecret(target, "")
}

func NewGRPCPolicyClientWithSecret(target, clientSecret string) (*GRPCPolicyClient, error) {
	return NewGRPCPolicyClientWithAuth(target, clientSecret, "")
}

func NewGRPCPolicyClientWithAuth(target, clientSecret, grpcToken string) (*GRPCPolicyClient, error) {
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &GRPCPolicyClient{conn: conn, clientSecret: clientSecret, grpcToken: grpcToken}, nil
}

func NewGRPCPolicyClientWithConn(conn grpc.ClientConnInterface) *GRPCPolicyClient {
	return NewGRPCPolicyClientWithConnAndSecret(conn, "")
}

func NewGRPCPolicyClientWithConnAndSecret(conn grpc.ClientConnInterface, clientSecret string) *GRPCPolicyClient {
	return NewGRPCPolicyClientWithConnAndAuth(conn, clientSecret, "")
}

func NewGRPCPolicyClientWithConnAndAuth(conn grpc.ClientConnInterface, clientSecret, grpcToken string) *GRPCPolicyClient {
	return &GRPCPolicyClient{conn: conn, clientSecret: clientSecret, grpcToken: grpcToken}
}

func NewGRPCTicketClient(target string) (*GRPCTicketClient, error) {
	return NewGRPCTicketClientWithSecret(target, "")
}

func NewGRPCTicketClientWithSecret(target, clientSecret string) (*GRPCTicketClient, error) {
	return NewGRPCTicketClientWithAuth(target, clientSecret, "")
}

func NewGRPCTicketClientWithAuth(target, clientSecret, grpcToken string) (*GRPCTicketClient, error) {
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &GRPCTicketClient{conn: conn, clientSecret: clientSecret, grpcToken: grpcToken}, nil
}

func NewGRPCTicketClientWithConn(conn grpc.ClientConnInterface) *GRPCTicketClient {
	return NewGRPCTicketClientWithConnAndSecret(conn, "")
}

func NewGRPCTicketClientWithConnAndSecret(conn grpc.ClientConnInterface, clientSecret string) *GRPCTicketClient {
	return NewGRPCTicketClientWithConnAndAuth(conn, clientSecret, "")
}

func NewGRPCTicketClientWithConnAndAuth(conn grpc.ClientConnInterface, clientSecret, grpcToken string) *GRPCTicketClient {
	return &GRPCTicketClient{conn: conn, clientSecret: clientSecret, grpcToken: grpcToken}
}

func NewGRPCEventClient(target string) (*GRPCEventClient, error) {
	return NewGRPCEventClientWithSecret(target, "")
}

func NewGRPCEventClientWithSecret(target, clientSecret string) (*GRPCEventClient, error) {
	return NewGRPCEventClientWithAuth(target, clientSecret, "")
}

func NewGRPCEventClientWithAuth(target, clientSecret, grpcToken string) (*GRPCEventClient, error) {
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &GRPCEventClient{conn: conn, clientSecret: clientSecret, grpcToken: grpcToken}, nil
}

func NewGRPCEventClientWithConn(conn grpc.ClientConnInterface) *GRPCEventClient {
	return NewGRPCEventClientWithConnAndSecret(conn, "")
}

func NewGRPCEventClientWithConnAndSecret(conn grpc.ClientConnInterface, clientSecret string) *GRPCEventClient {
	return NewGRPCEventClientWithConnAndAuth(conn, clientSecret, "")
}

func NewGRPCEventClientWithConnAndAuth(conn grpc.ClientConnInterface, clientSecret, grpcToken string) *GRPCEventClient {
	return &GRPCEventClient{conn: conn, clientSecret: clientSecret, grpcToken: grpcToken}
}

func NewGRPCConfigClient(target string) (*GRPCConfigClient, error) {
	return NewGRPCConfigClientWithSecret(target, "")
}

func NewGRPCConfigClientWithSecret(target, clientSecret string) (*GRPCConfigClient, error) {
	return NewGRPCConfigClientWithAuth(target, clientSecret, "")
}

func NewGRPCConfigClientWithAuth(target, clientSecret, grpcToken string) (*GRPCConfigClient, error) {
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &GRPCConfigClient{conn: conn, clientSecret: clientSecret, grpcToken: grpcToken}, nil
}

func NewGRPCConfigClientWithConn(conn grpc.ClientConnInterface) *GRPCConfigClient {
	return NewGRPCConfigClientWithConnAndSecret(conn, "")
}

func NewGRPCConfigClientWithConnAndSecret(conn grpc.ClientConnInterface, clientSecret string) *GRPCConfigClient {
	return NewGRPCConfigClientWithConnAndAuth(conn, clientSecret, "")
}

func NewGRPCConfigClientWithConnAndAuth(conn grpc.ClientConnInterface, clientSecret, grpcToken string) *GRPCConfigClient {
	return &GRPCConfigClient{conn: conn, clientSecret: clientSecret, grpcToken: grpcToken}
}

func (c *GRPCPolicyClient) Evaluate(ctx context.Context, req types.PolicyEvaluateRequest) (types.PolicyDecision, error) {
	response, err := captchav1.NewPolicyServiceClient(c.conn).Evaluate(
		withGRPCAuth(ctx, c.clientSecret, c.grpcToken),
		grpccontract.PolicyEvaluateRequestToProto(req),
	)
	if err != nil {
		return types.PolicyDecision{}, err
	}
	return grpccontract.PolicyDecisionFromProto(response), nil
}

func (c *GRPCTicketClient) Consume(ctx context.Context, req types.TicketVerifyRequest) (types.TicketVerifyResponse, error) {
	response, err := captchav1.NewTicketServiceClient(c.conn).ConsumeTicket(
		withGRPCAuth(ctx, c.clientSecret, c.grpcToken),
		grpccontract.TicketVerifyRequestToProto(req),
	)
	if err != nil {
		return types.TicketVerifyResponse{}, err
	}
	return grpccontract.TicketVerifyResponseFromProto(response), nil
}

func (c *GRPCEventClient) Report(ctx context.Context, events []types.AuditEvent) (types.ReportResult, error) {
	result, err := captchav1.NewEventServiceClient(c.conn).Report(
		withGRPCAuth(ctx, c.clientSecret, c.grpcToken),
		grpccontract.EventBatchToProto(events),
	)
	if err != nil {
		return types.ReportResult{}, err
	}
	return grpccontract.ReportResultFromProto(result), nil
}

func (c *GRPCConfigClient) GetConfig(ctx context.Context, clientID string) (types.ConfigSnapshot, error) {
	snapshot, err := captchav1.NewConfigServiceClient(c.conn).GetConfig(
		withGRPCAuth(ctx, c.clientSecret, c.grpcToken),
		&captchav1.ConfigRequest{ClientId: clientID},
	)
	if err != nil {
		return types.ConfigSnapshot{}, err
	}
	return grpccontract.ConfigSnapshotFromProto(snapshot), nil
}

func (c *GRPCConfigClient) WatchConfig(ctx context.Context, clientID string, onSnapshot func(types.ConfigSnapshot)) error {
	stream, err := captchav1.NewConfigServiceClient(c.conn).WatchConfig(
		withGRPCAuth(ctx, c.clientSecret, c.grpcToken),
		&captchav1.ConfigRequest{ClientId: clientID},
	)
	if err != nil {
		return err
	}
	for {
		snapshot, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		onSnapshot(grpccontract.ConfigSnapshotFromProto(snapshot))
	}
}

func withClientSecret(ctx context.Context, value string) context.Context {
	return withGRPCAuth(ctx, value, "")
}

func withGRPCAuth(ctx context.Context, clientSecret, grpcToken string) context.Context {
	values := make([]string, 0, 4)
	clientSecret = strings.TrimSpace(clientSecret)
	if clientSecret != "" {
		values = append(values, "x-captcha-client-secret", clientSecret)
	}
	grpcToken = strings.TrimSpace(grpcToken)
	if grpcToken != "" {
		values = append(values, "x-captcha-grpc-token", grpcToken)
	}
	if len(values) == 0 {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, values...)
}
