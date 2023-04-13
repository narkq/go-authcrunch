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
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func TestValidateConfig(t *testing.T) {
	testcases := []struct {
		name      string
		config    *Config
		want      *Config
		shouldErr bool
		err       error
	}{
		{
			name: "validate telegram oauth config",
			config: &Config{
				Name:     "telegram",
				Realm:    "telegram",
				BotToken: "123456:QWERTYASDFGHZXCVBN",
				UserGroups: []string{
					"@cat_pics",
					"100200300",
				},
			},
			want: &Config{
				Name:     "telegram",
				Realm:    "telegram",
				BotToken: "123456:QWERTYASDFGHZXCVBN",
				UserGroups: []string{
					"@cat_pics",
					"100200300",
				},
				// After the validation.
				AuthorizationURL:          "https://oauth.telegram.org/auth",
				MaxAuthenticationReplyAge: time.Minute,
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-telegram la-2x",
					Color:           "white",
					BackgroundColor: "#0088cc",
					Text:            "Telegram",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "test empty config name",
			config: &Config{
				Realm: "telegram",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigureNameEmpty,
		},
		{
			name: "test empty config realm",
			config: &Config{
				Name: "telegram",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfigureRealmEmpty,
		},
		{
			name: "test empty bot token",
			config: &Config{
				Name:  "telegram",
				Realm: "telegram",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("bot token not found"),
		},
		{
			name: "test invalid bot token",
			config: &Config{
				Name:     "telegram",
				Realm:    "telegram",
				BotToken: "qwerty",
			},
			shouldErr: true,
			err:       errors.ErrIdentityProviderConfig.WithArgs("bot token must have exactly two parts separated by a colon"),
		},
		{
			name: "test valid authorization_url",
			config: &Config{
				Name:             "telegram",
				Realm:            "telegram",
				BotToken:         "123456:QWERTYASDFGHZXCVBN",
				AuthorizationURL: "https://oauth.tg.dev/auth",
			},
			want: &Config{
				Name:     "telegram",
				Realm:    "telegram",
				BotToken: "123456:QWERTYASDFGHZXCVBN",
				// After the validation.
				AuthorizationURL:          "https://oauth.tg.dev/auth",
				MaxAuthenticationReplyAge: time.Minute,
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-telegram la-2x",
					Color:           "white",
					BackgroundColor: "#0088cc",
					Text:            "Telegram",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "test invalid authorization_url",
			config: &Config{
				Name:             "telegram",
				Realm:            "telegram",
				BotToken:         "123456:QWERTYASDFGHZXCVBN",
				AuthorizationURL: "***",
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf(
					"authorization_url must be a valid URL, got %q instead",
					"***",
				),
			),
		},
		{
			name: "test valid max_authentication_reply_age",
			config: &Config{
				Name:                      "telegram",
				Realm:                     "telegram",
				BotToken:                  "123456:QWERTYASDFGHZXCVBN",
				MaxAuthenticationReplyAge: time.Hour,
			},
			want: &Config{
				Name:     "telegram",
				Realm:    "telegram",
				BotToken: "123456:QWERTYASDFGHZXCVBN",
				// After the validation.
				AuthorizationURL:          "https://oauth.telegram.org/auth",
				MaxAuthenticationReplyAge: time.Hour,
				LoginIcon: &icons.LoginIcon{
					ClassName:       "lab la-telegram la-2x",
					Color:           "white",
					BackgroundColor: "#0088cc",
					Text:            "Telegram",
					TextColor:       "#37474f",
				},
			},
		},
		{
			name: "test invalid max_authentication_reply_age",
			config: &Config{
				Name:                      "telegram",
				Realm:                     "telegram",
				BotToken:                  "123456:QWERTYASDFGHZXCVBN",
				MaxAuthenticationReplyAge: -1 * time.Second,
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfig.WithArgs(
				"max_authentication_reply_age must not be negative",
			),
		},
		{
			name: "test invalid user group",
			config: &Config{
				Name:     "telegram",
				Realm:    "telegram",
				BotToken: "123456:QWERTYASDFGHZXCVBN",
				UserGroups: []string{
					"zzz",
				},
			},
			shouldErr: true,
			err: errors.ErrIdentityProviderConfig.WithArgs(
				fmt.Errorf(
					"telegram user group must be either a '@username' or chat id (integer), got %q instead",
					"zzz",
				),
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}

			err := tc.config.Validate()

			if tests.EvalErrWithLog(t, err, "Config.Validate", tc.shouldErr, tc.err, msgs) {
				return
			}

			tests.EvalObjectsWithLog(t, "Config.Content", tc.want, tc.config, msgs)
		})
	}
}
