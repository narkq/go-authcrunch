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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func (b *IdentityProvider) validateResponse(params url.Values) (map[string]interface{}, error) {
	var hash string

	var keys []string
	for k, v := range params {
		if k == "hash" {
			hash = v[0]
		} else {
			keys = append(keys, k)
		}
	}

	sort.Strings(keys)

	var buf bytes.Buffer
	m := make(map[string]interface{})
	for i, k := range keys {
		if i > 0 {
			buf.WriteString("\n")
		}
		v := params[k][0]
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(v)
		m[k] = v
	}

	mac := hmac.New(sha256.New, b.botTokenHash)
	mac.Write(buf.Bytes())

	if hash != hex.EncodeToString(mac.Sum(nil)) {
		return nil, errors.ErrIdentityProviderTelegramHashValidationFailed.WithArgs(m)
	}

	val, exists := m["auth_date"]
	if !exists {
		return nil, errors.ErrIdentityProviderTelegramAuthDateMissing.WithArgs(m)
	}

	authDate, isString := val.(string)
	if !isString {
		return nil, errors.ErrIdentityProviderTelegramAuthDateInvalid.WithArgs(val)
	}

	unixTime, err := strconv.ParseInt(authDate, 10, 64)
	if err != nil {
		return nil, errors.ErrIdentityProviderTelegramAuthDateInvalid.WithArgs(authDate)
	}

	elapsed := time.Since(time.Unix(unixTime, 0))
	if elapsed > b.maxAuthenticationReplyAge {
		return nil, errors.ErrIdentityProviderTelegramTokenExpired.WithArgs(elapsed.String(), b.maxAuthenticationReplyAge.String())
	}

	return m, nil
}
