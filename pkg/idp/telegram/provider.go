// Copyright 2023 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package telegram

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// IdentityProvider represents Telegram-based identity provider.
type IdentityProvider struct {
	config           *Config
	authorizationURL string
	botID            string
	botToken         string
	// these are needed for validating authentication reply
	botTokenHash              []byte
	maxAuthenticationReplyAge time.Duration
	// The user groups that will be checked for membership via the Telegram API.
	// If user is a member of a group, that group will be included into
	// user roles issued by the portal.
	userGroups    []string
	logger        *zap.Logger
	browserConfig *browserConfig
	configured    bool
}

// NewIdentityProvider returns an instance of IdentityProvider.
func NewIdentityProvider(cfg *Config, logger *zap.Logger) (*IdentityProvider, error) {
	if logger == nil {
		return nil, errors.ErrIdentityProviderConfigureLoggerNotFound
	}

	b := &IdentityProvider{
		config: cfg,
		logger: logger,
	}

	if err := b.config.Validate(); err != nil {
		return nil, err
	}

	return b, nil
}

// GetRealm return authentication realm.
func (b *IdentityProvider) GetRealm() string {
	return b.config.Realm
}

// GetName return the name associated with this identity provider.
func (b *IdentityProvider) GetName() string {
	return b.config.Name
}

// GetKind returns the authentication method associated with this identity provider.
func (b *IdentityProvider) GetKind() string {
	return "oauth"
}

// Configured returns true if the identity provider was configured.
func (b *IdentityProvider) Configured() bool {
	return b.configured
}

// GetConfig returns IdentityProvider configuration.
func (b *IdentityProvider) GetConfig() map[string]interface{} {
	var m map[string]interface{}
	j, _ := json.Marshal(b.config)
	json.Unmarshal(j, &m)
	return m
}

// Request performs the requested identity provider operation.
func (b *IdentityProvider) Request(op operator.Type, r *requests.Request) error {
	switch op {
	case operator.Authenticate:
		return b.Authenticate(r)
	}
	return errors.ErrOperatorNotSupported.WithArgs(op)
}

// Configure configures IdentityProvider.
func (b *IdentityProvider) Configure() error {
	b.authorizationURL = b.config.AuthorizationURL

	if b.config.TLSInsecureSkipVerify {
		b.browserConfig = &browserConfig{
			TLSInsecureSkipVerify: true,
		}
	}

	b.userGroups = b.config.UserGroups

	b.botToken = b.config.BotToken
	b.botID, _, _ = strings.Cut(b.config.BotToken, ":")

	botTokenHash := sha256.New()
	botTokenHash.Write([]byte(b.config.BotToken))
	b.botTokenHash = botTokenHash.Sum(nil)

	b.maxAuthenticationReplyAge = b.config.MaxAuthenticationReplyAge

	b.logger.Info(
		"successfully configured Telegram identity provider",
		zap.String("bot_id", b.botID),
		zap.String("authorization_url", b.authorizationURL),
		zap.Duration("max_authentication_reply_age", b.maxAuthenticationReplyAge),
		zap.Any("login_icon", b.config.LoginIcon),
	)

	b.configured = true
	return nil
}

// GetLoginIcon returns the instance of the icon associated with the provider.
func (b *IdentityProvider) GetLoginIcon() *icons.LoginIcon {
	return b.config.LoginIcon
}

// GetLogoutURL returns the logout URL associated with the provider.
func (b *IdentityProvider) GetLogoutURL() string {
	return ""
}

// GetDriver returns the name of the driver associated with the provider.
func (b *IdentityProvider) GetDriver() string {
	return driver
}

// GetIdentityTokenCookieName returns the name of the identity token cookie associated with the provider.
func (b *IdentityProvider) GetIdentityTokenCookieName() string {
	return ""
}
