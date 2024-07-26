package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"time"

	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	DefaultSocketPath = "/tmp/spire-server/private/api.sock"
	FormatPEM         = "pem"
	FormatSPIFFE      = "spiffe"
)

var (
	action = flag.String("action", "X", "")
	id     = flag.String("id", "", "")
)

func Dial(addr net.Addr) (*grpc.ClientConn, error) {
	return grpc.Dial(addr.String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithBlock(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithReturnConnectionError())
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", addr)
}

func getUnixAddrWithAbsPath(path string) (*net.UnixAddr, error) {
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for socket path: %w", err)
	}

	return &net.UnixAddr{
		Name: pathAbs,
		Net:  "unix",
	}, nil
}

func main() {
	flag.Parse()
	fmt.Println(*action)

	addr, err := getUnixAddrWithAbsPath(DefaultSocketPath)
	if err != nil {
		log.Fatalf("Faied to get addr: %v\n", err)
	}

	conn, err := Dial(addr)
	if err != nil {
		log.Fatalf("Faied to get dial: %v\n", err)
	}

	cli := localauthorityv1.NewLocalAuthorityClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	states := make(map[string]*localauthorityv1.AuthorityState)

	switch *action {
	case "XG":
		resp, err := cli.GetX509AuthorityState(ctx, &localauthorityv1.GetX509AuthorityStateRequest{})
		if err != nil {
			log.Fatalf("Failed to get authority: %v\n", err)
		}
		states["OLD"] = resp.Old
		states["ACTIVE"] = resp.Active
		states["PREPARED"] = resp.Prepared

	case "XP":
		resp, err := cli.PrepareX509Authority(ctx, &localauthorityv1.PrepareX509AuthorityRequest{})
		if err != nil {
			log.Fatalf("Failed to prepare authority: %v\n", err)
		}
		states["PREPARED"] = resp.PreparedAuthority

	case "XA":
		resp, err := cli.ActivateX509Authority(ctx, &localauthorityv1.ActivateX509AuthorityRequest{
			AuthorityId: *id,
		})
		if err != nil {
			log.Fatalf("Failed to activate authority: %v\n", err)
		}
		states["ACTIVE"] = resp.ActivatedAuthority

	case "XT":
		resp, err := cli.TaintX509Authority(ctx, &localauthorityv1.TaintX509AuthorityRequest{
			AuthorityId: *id,
		})
		if err != nil {
			log.Fatalf("Failed to taint authority: %v\n", err)
		}
		states["TAINTED"] = resp.TaintedAuthority

	case "XUT":
		_, err := cli.TaintX509UpstreamAuthority(ctx, &localauthorityv1.TaintX509UpstreamAuthorityRequest{
			SubjectKeyId: *id,
		})
		if err != nil {
			log.Fatalf("Failed to taint upstream authority: %v\n", err)
		}
		states["TAINTED"] = &localauthorityv1.AuthorityState{}

	case "XR":
		resp, err := cli.RevokeX509Authority(ctx, &localauthorityv1.RevokeX509AuthorityRequest{
			AuthorityId: *id,
		})
		if err != nil {
			log.Fatalf("Failed to revoke authority: %v\n", err)
		}
		states["REVOKED"] = resp.RevokedAuthority

	case "JG":
		resp, err := cli.GetJWTAuthorityState(ctx, &localauthorityv1.GetJWTAuthorityStateRequest{})
		// resp, err := cli.GetX509AuthorityState(ctx, &localauthorityv1.GetX509AuthorityStateRequest{})
		if err != nil {
			log.Fatalf("Failed to get authority: %v\n", err)
		}
		states["OLD"] = resp.Old

		states["ACTIVE"] = resp.Active
		states["PREPARED"] = resp.Prepared

	case "JP":
		resp, err := cli.PrepareJWTAuthority(ctx, &localauthorityv1.PrepareJWTAuthorityRequest{})
		// resp, err := cli.PrepareX509Authority(ctx, &localauthorityv1.PrepareX509AuthorityRequest{})
		if err != nil {
			log.Fatalf("Failed to prepare authority: %v\n", err)
		}
		states["PREPARED"] = resp.PreparedAuthority

	case "JA":
		// resp, err := cli.ActivateX509Authority(ctx, &localauthorityv1.ActivateX509AuthorityRequest{
		resp, err := cli.ActivateJWTAuthority(ctx, &localauthorityv1.ActivateJWTAuthorityRequest{
			AuthorityId: *id,
		})
		if err != nil {
			log.Fatalf("Failed to activate authority: %v\n", err)
		}
		states["ACTIVE"] = resp.ActivatedAuthority

	case "JT":
		// resp, err := cli.TaintX509Authority(ctx, &localauthorityv1.TaintX509AuthorityRequest{
		resp, err := cli.TaintJWTAuthority(ctx, &localauthorityv1.TaintJWTAuthorityRequest{
			AuthorityId: *id,
		})
		if err != nil {
			log.Fatalf("Failed to taint authority: %v\n", err)
		}
		states["TAINTED"] = resp.TaintedAuthority

	case "JR":
		// resp, err := cli.RevokeX509Authority(ctx, &localauthorityv1.RevokeX509AuthorityRequest{
		resp, err := cli.RevokeJWTAuthority(ctx, &localauthorityv1.RevokeJWTAuthorityRequest{
			AuthorityId: *id,
		})
		if err != nil {
			log.Fatalf("Failed to revoke authority: %v\n", err)
		}
		states["REVOKED"] = resp.RevokedAuthority

	default:
		log.Fatalf("unsuppported option: %v\n", action)
	}

	for k, v := range states {
		log.Printf("State %v:\n", k)
		if v != nil {
			log.Printf("- AuthorityID: %v\n", v.AuthorityId)
			log.Printf("- ExpiresAt: %v\n", v.ExpiresAt)
		}
	}

}
