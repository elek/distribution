package storj

import (
	"context"
	"fmt"
	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/registry/auth"
	"net/http"
	"storj.io/gateway-mt/pkg/authclient"
	"strings"
)

type grantKey = struct{}

func newAccessController(options map[string]interface{}) (auth.AccessController, error) {
	cfg := authclient.Config{
		BaseURL: options["url"].(string),
		Token:   options["token"].(string),
	}
	client := authclient.New(cfg)
	return &accessController{
		client: client,
	}, nil
}

type accessController struct {
	client *authclient.AuthClient
}

func hasAction(actions []string, action string) bool {
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}

func (a accessController) Authorized(ctx context.Context, access ...auth.Access) (context.Context, error) {
	actions := []string{}
	repoName := ""
	for _, acc := range access {
		fmt.Printf("access: %s/%s/%s\n", acc.Class, acc.Type, acc.Action)
		if acc.Type == "repository" {
			actions = append(actions, acc.Action)
			repoName = acc.Name
		}
	}

	if len(actions) > 0 {
		id := strings.Split(repoName, "/")[0]
		resp, err := a.client.Resolve(ctx, id, "127.0.0.1")
		if err != nil {
			return nil, &challenge{
				realm: "registry",
				err:   err,
			}
		}

		if !resp.Public || hasAction(actions, "push") {
			req, err := dcontext.GetRequest(ctx)
			if err != nil {
				return nil, err
			}

			username, password, ok := req.BasicAuth()
			if !ok {
				return nil, &challenge{
					realm: "registry",
					err:   auth.ErrInvalidCredential,
				}
			}
			if username != resp.AccessGrant || password != resp.SecretKey {
				return nil, &challenge{
					realm: "registry",
					err:   auth.ErrInvalidCredential,
				}
			}
		}
		return context.WithValue(ctx, grantKey{}, resp.AccessGrant), nil

	}

	return ctx, nil
}

func GetGrant(ctx context.Context) string {
	value := ctx.Value(grantKey{})
	if value == nil {
		return ""
	}
	return value.(string)
}

func init() {
	auth.Register("storj", newAccessController)
}

// challenge implements the auth.Challenge interface.
type challenge struct {
	realm string
	err   error
}

var _ auth.Challenge = challenge{}

// SetHeaders sets the basic challenge header on the response.
func (ch challenge) SetHeaders(r *http.Request, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", ch.realm))
}

func (ch challenge) Error() string {
	return fmt.Sprintf("basic authentication challenge for realm %q: %s", ch.realm, ch.err)
}
