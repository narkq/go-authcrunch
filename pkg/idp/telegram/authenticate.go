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
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"

	"go.uber.org/zap"
)

// Authenticate performs authentication.
func (b *IdentityProvider) Authenticate(r *requests.Request) error {
	reqPath := r.Upstream.BaseURL + path.Join(r.Upstream.BasePath, r.Upstream.Method, r.Upstream.Realm)
	r.Response.Code = http.StatusBadRequest

	if strings.HasSuffix(r.Upstream.Request.URL.Path, "/authorization-code-callback") {
		reqParams := r.Upstream.Request.URL.Query()
		b.logger.Debug(
			"received Telegram auth response",
			zap.String("session_id", r.Upstream.SessionID),
			zap.String("request_id", r.ID),
			zap.Any("params", reqParams),
		)
		m, err := b.validateResponse(reqParams)
		if err != nil {
			return err
		}

		m, err = b.fetchClaims(m)
		if err != nil {
			return errors.ErrIdentityProviderTelegramFetchClaimsFailed.WithArgs(err)
		}

		r.Response.Payload = m
		r.Response.Code = http.StatusOK
		b.logger.Debug(
			"decoded user data from Telegram authorization response",
			zap.String("request_id", r.ID),
			zap.Any("claims", m),
		)
		return nil
	}
	r.Response.Code = http.StatusFound
	params := url.Values{}
	params.Set("bot_id", b.botID)
	params.Set("origin", r.Upstream.BaseURL)
	params.Set("return_to", reqPath+"/authorization-code-js-callback")

	r.Response.RedirectURL = b.authorizationURL + "?" + params.Encode()

	b.logger.Debug(
		"redirecting to Telegram auth endpoint",
		zap.String("request_id", r.ID),
		zap.String("redirect_url", r.Response.RedirectURL),
	)
	return nil
}
