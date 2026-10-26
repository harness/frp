// Copyright 2026 The frp Authors
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

package nathole

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/pion/stun/v3"
)

func testSTUNResponse(t *testing.T, raw []byte) (*stunResponse, error) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	c, err := listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.messageChan <- &Message{Body: raw}
	return c.doSTUNRequest(server.LocalAddr().String())
}

func TestSTUNResponseShortAddressAttributes(t *testing.T) {
	for name, attr := range map[string]stun.AttrType{
		"mapped": stun.AttrMappedAddress, "xor-mapped": stun.AttrXORMappedAddress,
		"changed": stun.AttrChangedAddress, "other": stun.AttrOtherAddress,
	} {
		for size := 0; size <= 4; size++ {
			t.Run(fmt.Sprintf("%s/%d", name, size), func(t *testing.T) {
				// Fill the receive buffer so the final attribute cannot read into
				// spare capacity. A zero-length XOR address used to panic here.
				raw := make([]byte, 1024)
				binary.BigEndian.PutUint16(raw[0:2], 0x0101) // Binding success.
				binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)-20))
				binary.BigEndian.PutUint32(raw[4:8], 0x2112a442)
				paddedSize := (size + 3) &^ 3
				addressOffset := len(raw) - 4 - paddedSize
				binary.BigEndian.PutUint16(raw[20:22], uint16(stun.AttrSoftware))
				binary.BigEndian.PutUint16(raw[22:24], uint16(addressOffset-24))
				binary.BigEndian.PutUint16(raw[addressOffset:addressOffset+2], uint16(attr))
				binary.BigEndian.PutUint16(raw[addressOffset+2:addressOffset+4], uint16(size))
				resp, err := testSTUNResponse(t, raw)
				if err != nil {
					t.Fatal(err)
				}
				if resp.externalAddr != "" || resp.otherAddr != "" {
					t.Fatalf("malformed address accepted: %+v", resp)
				}
			})
		}
	}
}

func TestSTUNResponseXORMappedAddress(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		t.Run(ip, func(t *testing.T) {
			address := &stun.XORMappedAddress{IP: net.ParseIP(ip), Port: 4321}
			message, err := stun.Build(stun.TransactionID, stun.BindingSuccess, address)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := testSTUNResponse(t, message.Raw)
			if err != nil {
				t.Fatal(err)
			}
			if resp.externalAddr != address.String() {
				t.Fatalf("external address = %q, want %q", resp.externalAddr, address.String())
			}
		})
	}
}
