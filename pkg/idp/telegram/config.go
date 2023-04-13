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
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const driver = "telegram"

// Config holds the configuration for the IdentityProvider.
type Config struct {
	Name     string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Realm    string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	BotToken string `json:"client_secret,omitempty" xml:"client_secret,omitempty" yaml:"client_secret,omitempty"`

	// The user groups that will be checked for membership via Telegram API.
	UserGroups []string `json:"user_group_filters,omitempty" xml:"user_group_filters,omitempty" yaml:"user_group_filters,omitempty"`

	AuthorizationURL string `json:"authorization_url,omitempty" xml:"authorization_url,omitempty" yaml:"authorization_url,omitempty"`

	TLSInsecureSkipVerify bool `json:"tls_insecure_skip_verify,omitempty" xml:"tls_insecure_skip_verify,omitempty" yaml:"tls_insecure_skip_verify,omitempty"`

	MaxAuthenticationReplyAge time.Duration `json:"max_authentication_reply_age,omitempty" xml:"max_authentication_reply_age,omitempty" yaml:"max_authentication_reply_age,omitempty"`

	// LoginIcon is the UI login icon attributes.
	LoginIcon *icons.LoginIcon `json:"login_icon,omitempty" xml:"login_icon,omitempty" yaml:"login_icon,omitempty"`
}

// Validate validates identity store configuration.
func (cfg *Config) Validate() error {
	if cfg.Name == "" {
		return errors.ErrIdentityProviderConfigureNameEmpty
	}

	if cfg.Realm == "" {
		return errors.ErrIdentityProviderConfigureRealmEmpty
	}

	if cfg.BotToken == "" {
		return errors.ErrIdentityProviderConfig.WithArgs("bot token not found")
	}

	if tokenParts := strings.Split(cfg.BotToken, ":"); len(tokenParts) != 2 || len(tokenParts[0]) == 0 || len(tokenParts[1]) == 0 {
		return errors.ErrIdentityProviderConfig.WithArgs("bot token must have exactly two parts separated by a colon")
	}

	if cfg.AuthorizationURL != "" {
		if url, err := url.Parse(cfg.AuthorizationURL); err != nil || url.Host == "" {
			return errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf("authorization_url must be a valid URL, got %q instead", cfg.AuthorizationURL),
			)
		}
	} else {
		cfg.AuthorizationURL = "https://oauth.telegram.org/auth"
	}

	if cfg.MaxAuthenticationReplyAge < 0 {
		return errors.ErrIdentityProviderConfig.WithArgs("max_authentication_reply_age must not be negative")
	}

	if cfg.MaxAuthenticationReplyAge == 0 {
		cfg.MaxAuthenticationReplyAge = time.Minute
	}

	for _, group := range cfg.UserGroups {
		if strings.HasPrefix(group, "@") {
			continue
		}

		if _, err := strconv.ParseInt(group, 10, 64); err != nil {
			return errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf("telegram user group must be either a '@username' or chat id (integer), got %q instead", group),
			)
		}
	}

	// Configure UI login icon.
	if cfg.LoginIcon == nil {
		cfg.LoginIcon = icons.NewLoginIcon(driver)
	} else {
		cfg.LoginIcon.Configure(driver)
	}

	return nil
}

// MatchDriver checks if oath provider config specifies telegram driver
func MatchDriver(cfg map[string]interface{}) bool {
	v, exists := cfg["driver"]
	if !exists {
		return false
	}
	drv, ok := v.(string)
	if !ok {
		return false
	}
	return drv == driver
}
