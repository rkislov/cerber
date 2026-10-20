// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var ErrForbidden = errors.New("forbidden")
var ErrInvalid = errors.New("invalid administration request")
var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,63}$`)

type User struct {
	AuthMethod   string `json:"auth_method,omitempty"`
	Username     string `json:"username"`
	Role         string `json:"role"`
	Disabled     bool   `json:"disabled"`
	Version      int    `json:"-"`
	PasswordHash string `json:"-"`
}

func ValidRole(v string) bool {
	return v == "administrator" || v == "operator" || v == "viewer" || v == "analyst"
}
func ValidUsername(v string) bool { return usernamePattern.MatchString(v) }
func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 256 {
		return "", fmt.Errorf("password must be 12–256 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		return "", err
	}
	return "pbkdf2-sha256-600000$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(key), nil
}
func CheckPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 3 || parts[0] != "pbkdf2-sha256-600000" || len(password) > 256 {
		return false
	}
	salt, e := hex.DecodeString(parts[1])
	want, e2 := hex.DecodeString(parts[2])
	if e != nil || e2 != nil || len(salt) != 16 || len(want) != 32 {
		return false
	}
	got, e := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	return e == nil && subtle.ConstantTimeCompare(got, want) == 1
}

type principalKey struct{}

func WithPrincipal(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, principalKey{}, u)
}
func Principal(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(principalKey{}).(User)
	return u, ok
}

type Command struct {
	Action       string `json:"action"`
	Username     string `json:"username,omitempty"`
	Role         string `json:"role,omitempty"`
	Disabled     bool   `json:"disabled,omitempty"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"-"`
	AgentID      string `json:"agent_id,omitempty"`
	AssetID      string `json:"asset_id,omitempty"`
	Name         string `json:"name,omitempty"`
	IP           string `json:"ip,omitempty"`
	TokenHash    string `json:"-"`
}
