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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

type groupMember struct {
	Status string `json:"status"`
}

type groupMembershipReply struct {
	Ok     bool        `json:"ok"`
	Result groupMember `json:"result"`
}

func (b *IdentityProvider) fetchClaims(tokenData map[string]interface{}) (map[string]interface{}, error) {
	for _, k := range []string{"id", "username"} {
		if _, exists := tokenData[k]; !exists {
			return nil, fmt.Errorf("token response has no %s field", k)
		}
	}

	userID, isStr := tokenData["id"].(string)
	if !isStr {
		return nil, fmt.Errorf("id is not a string: %v", tokenData["id"])
	}

	username, isStr := tokenData["username"].(string)
	if !isStr {
		return nil, fmt.Errorf("username is not a string: %v", tokenData["username"])
	}

	m := make(map[string]interface{})

	m["sub"] = "t.me/" + username
	m["name"] = username

	if picture, exists := tokenData["photo_url"]; exists {
		m["picture"] = picture
	}

	var userGroups []string

	for _, groupID := range b.userGroups {
		roles, err := b.fetchGroupRoleMembership(userID, groupID)
		if err != nil {
			b.logger.Error(
				"Failed fetching user group role membership",
				zap.String("identity_provider_name", b.config.Name),
				zap.String("user_id", userID),
				zap.String("group_id", groupID),
				zap.Error(err),
			)
		}

		for _, role := range roles {
			userGroups = append(userGroups, fmt.Sprintf("t.me/group/%s/%s", groupID, role))
		}
	}

	if len(userGroups) > 0 {
		m["groups"] = userGroups
	}
	return m, nil
}

func (b *IdentityProvider) fetchGroupRoleMembership(userID string, groupID string) ([]string, error) {
	reqURL := fmt.Sprintf("https://api.telegram.org/bot%s/getChatMember", b.botToken)

	// Create new http client instance.
	cli, err := b.newBrowser()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("chat_id", groupID)
	q.Set("user_id", userID)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "application/json")

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	b.logger.Debug(
		"Received group membership infomation",
		zap.String("url", strings.Replace(req.URL.String(), b.botToken, "XXX:XXX", 1)),
		zap.Any("body", respBody),
	)

	membershipData := groupMembershipReply{}
	if err := json.Unmarshal(respBody, &membershipData); err != nil {
		return nil, err
	}

	switch membershipData.Result.Status {
	case "creator":
		return []string{"owners", "admins", "members"}, nil
	case "administrator":
		return []string{"admins", "members"}, nil
	case "member":
		return []string{"members"}, nil
	// case "restricted":
	// case "left":
	// case "kicked":
	default:
		return nil, nil
	}
}
