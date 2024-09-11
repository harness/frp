// Copyright 2019 fatedier, fatedier@gmail.com
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

package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/fatedier/frp/pkg/util/util"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func init() {
	RegisterProxyFactory(reflect.TypeOf(&v1.TCPProxyConfig{}), NewTCPProxy)
}

type TCPProxy struct {
	*BaseProxy
	cfg *v1.TCPProxyConfig

	realBindPort int
}

func NewTCPProxy(baseProxy *BaseProxy) Proxy {
	unwrapped, ok := baseProxy.GetConfigurer().(*v1.TCPProxyConfig)
	if !ok {
		return nil
	}
	baseProxy.usedPortsNum = 1
	return &TCPProxy{
		BaseProxy: baseProxy,
		cfg:       unwrapped,
	}
}

func (pxy *TCPProxy) Run() (remoteAddr string, err error) {
	xl := pxy.xl
	if pxy.cfg.LoadBalancer.Group != "" {
		l, realBindPort, errRet := pxy.rc.TCPGroupCtl.Listen(pxy.name, pxy.cfg.LoadBalancer.Group, pxy.cfg.LoadBalancer.GroupKey,
			pxy.serverCfg.ProxyBindAddr, pxy.cfg.RemotePort)
		if errRet != nil {
			err = errRet
			return
		}
		defer func() {
			if err != nil {
				l.Close()
			}
		}()
		pxy.realBindPort = realBindPort
		pxy.listeners = append(pxy.listeners, l)
		xl.Info("tcp proxy listen port [%d] in group [%s]", pxy.cfg.RemotePort, pxy.cfg.LoadBalancer.Group)
	} else {
		pxy.realBindPort, err = pxy.rc.TCPPortManager.Acquire(pxy.name, pxy.cfg.RemotePort)
		if err != nil {
			return
		}
		defer func() {
			if err != nil {
				pxy.rc.TCPPortManager.Release(pxy.realBindPort)
			}
		}()

		if err = registerClient(pxy.BaseProxy.loginMsg.ApiKey, pxy.cfg.RemotePort, pxy.BaseProxy.serverCfg.HarnessEndpoint, false,
			pxy.BaseProxy.loginMsg.HarnessUsername, pxy.BaseProxy.loginMsg.HarnessPassword); err != nil {
			return
		}
		listener, errRet := net.Listen("tcp", net.JoinHostPort(pxy.serverCfg.ProxyBindAddr, strconv.Itoa(pxy.realBindPort)))
		if errRet != nil {
			err = errRet
			return
		}
		pxy.listeners = append(pxy.listeners, listener)
		xl.Info("tcp proxy listen port [%d]", pxy.cfg.RemotePort)
	}

	pxy.cfg.RemotePort = pxy.realBindPort
	remoteAddr = fmt.Sprintf(":%d", pxy.realBindPort)
	pxy.startCommonTCPListenersHandler()
	return
}

func registerClient(apiKey string, port int, endpoints string, shouldDelete bool,
	harnessUsername, harnessPassword string) (err error) {

	client := &http.Client{}

	if strings.Contains(endpoints, "localhost") {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client = &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		}
	}

	accoundId := util.ExtractBetweenDots(apiKey)

	if accoundId == "" {
		err = errors.New("token in login doesn't match format. Can't extract account ID")
		return
	}

	result := strings.Split(endpoints, ",")

	for _, endPoint := range result {
		endPoint = strings.TrimSpace(endPoint)
		url := fmt.Sprintf("%s/tunnel?accountIdentifier=%s", endPoint, accoundId)
		contentType := "application/json"

		var userCredentials string
		if harnessUsername != "" && harnessPassword != "" {
			userCredentials = fmt.Sprintf("%s:%s", harnessUsername, harnessPassword)
		}

		var payload []byte

		if userCredentials != "" {
			payload = []byte(fmt.Sprintf(`{"port": "%d", "userCredentials": "%s"}`, port, userCredentials))
		} else {
			payload = []byte(fmt.Sprintf(`{"port": "%d"}`, port))
		}

		var method string

		if shouldDelete {
			method = "DELETE"
		} else {
			method = "POST"
		}

		req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
		if err != nil {
			fmt.Println(err)
			continue
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("x-api-key", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error in validating API key %s\n", err.Error())
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fmt.Println("Response Status:", resp.Status)
			return nil
		}
	}

	return errors.New("Error registering frp client for account:" + accoundId)
}

func (pxy *TCPProxy) Close() {
	pxy.BaseProxy.Close()
	if pxy.cfg.LoadBalancer.Group == "" {
		pxy.rc.TCPPortManager.Release(pxy.realBindPort)
	}
}
