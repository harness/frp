// Copyright 2020 guylewin, guy@lewin.co.il
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

package auth

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/samber/lo"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
)

type TokenAuthSetterVerifier struct {
	additionalAuthScopes []v1.AuthScope
	token                string
}

func NewTokenAuth(additionalAuthScopes []v1.AuthScope, token string) *TokenAuthSetterVerifier {
	return &TokenAuthSetterVerifier{
		additionalAuthScopes: additionalAuthScopes,
		token:                token,
	}
}

func (auth *TokenAuthSetterVerifier) SetLogin(loginMsg *msg.Login) error {
	loginMsg.PrivilegeKey = util.GetAuthKey(auth.token, loginMsg.Timestamp)
	return nil
}

func (auth *TokenAuthSetterVerifier) SetPing(pingMsg *msg.Ping) error {
	if !lo.Contains(auth.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}

	pingMsg.Timestamp = time.Now().Unix()
	pingMsg.PrivilegeKey = util.GetAuthKey(auth.token, pingMsg.Timestamp)
	return nil
}

func (auth *TokenAuthSetterVerifier) SetNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !lo.Contains(auth.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}

	newWorkConnMsg.Timestamp = time.Now().Unix()
	newWorkConnMsg.PrivilegeKey = util.GetAuthKey(auth.token, newWorkConnMsg.Timestamp)
	return nil
}

func validateApiKey(apiKey string, endPoints string) error {

	accoundId := util.ExtractBetweenDots(apiKey)

	if accoundId == "" {
		fmt.Errorf("token in login doesn't match format. Can't extract account ID")
	}

	result := strings.Split(endPoints, ",")

	for _, endPoint := range result {
		endPoint = strings.TrimSpace(endPoint)
		reqUrl := endPoint + "/gateway/authz/api/acl"

		var formated = fmt.Sprintf(`{
    "permissions": [
      {
        "resourceScope": {
          "accountIdentifier": "%s",
          "orgIdentifier": "",
          "projectIdentifier": ""
        },
        "resourceType": "PIPLINE",
        "permission": "core_pipeline_view"
      }
    ]
  	}`, accoundId)

		req, err := http.NewRequest("POST", reqUrl, bytes.NewReader([]byte(formated)))
		if err != nil {
			return fmt.Errorf(err.Error())
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("x-api-key", apiKey)
		res, err := http.DefaultClient.Do(req)
		fmt.Println(err)
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
			continue
		}

		searchSubstring := `"permitted":true`
		bodyStr := string(body)
		fmt.Println(bodyStr)

		if !strings.Contains(bodyStr, searchSubstring) {
			fmt.Println(fmt.Errorf("API key is not valid"))
			continue
		}

		return nil
	}

	return errors.New("Validating API key client for account:" + accoundId)
}

func (auth *TokenAuthSetterVerifier) VerifyLogin(m *msg.Login, endPoint string) error {
	if !util.ConstantTimeEqString(util.GetAuthKey(auth.token, m.Timestamp), m.PrivilegeKey) {
		return fmt.Errorf("token in login doesn't match token from configuration")
	}

	if strings.Contains(endPoint, "localhost") {
		return nil
	}

	// var err error
	// if err = validateApiKey(m.ApiKey, endPoint); err != nil {
	// 	return err
	// }

	return nil
}

func (auth *TokenAuthSetterVerifier) VerifyPing(m *msg.Ping) error {
	if !lo.Contains(auth.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}

	if !util.ConstantTimeEqString(util.GetAuthKey(auth.token, m.Timestamp), m.PrivilegeKey) {
		return fmt.Errorf("token in heartbeat doesn't match token from configuration")
	}
	return nil
}

func (auth *TokenAuthSetterVerifier) VerifyNewWorkConn(m *msg.NewWorkConn) error {
	if !lo.Contains(auth.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}

	if !util.ConstantTimeEqString(util.GetAuthKey(auth.token, m.Timestamp), m.PrivilegeKey) {
		return fmt.Errorf("token in NewWorkConn doesn't match token from configuration")
	}
	return nil
}
