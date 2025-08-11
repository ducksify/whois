/*
 * Copyright 2014-2024 Li Kexian
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * RDAP wrapper tests for whois package
 */

package whois

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRDAPClient(t *testing.T) {
	client := NewRDAPClient()
	assert.NotNil(t, client)
	assert.NotNil(t, client.Client)
	assert.NotNil(t, client.httpClient)
}

func TestQueryRDAP(t *testing.T) {
	// Test domain query
	response, err := QueryRDAP("egger.ru")
	assert.Nil(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "domain", response.ObjectClassName)
	assert.Equal(t, "egger.ru", response.LdhName)
	assert.Equal(t, "egger.ru", response.UnicodeName)
	assert.NotEmpty(t, response.RawWhois)
	assert.NotEmpty(t, response.WhoisParsed)
	assert.Contains(t, response.RdapConformance, "rdap_level_0")
}

func TestRDAPResponseToJSON(t *testing.T) {
	response, err := QueryRDAP("egger.ru")
	assert.Nil(t, err)

	jsonData, err := response.ToJSON()
	assert.Nil(t, err)
	assert.NotEmpty(t, jsonData)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonData, &parsed)
	assert.Nil(t, err)
	assert.Equal(t, "domain", parsed["objectClassName"])
	assert.Equal(t, "egger.ru", parsed["ldhName"])
}

func TestRDAPClientQueryRDAP(t *testing.T) {
	client := NewRDAPClient()
	response, err := client.QueryRDAP("egger.ru")
	assert.Nil(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "domain", response.ObjectClassName)
}

func TestRDAPDomainParsing(t *testing.T) {
	client := NewRDAPClient()
	response, err := client.QueryRDAP("egger.ru")
	assert.Nil(t, err)

	// Check domain-specific fields
	assert.Equal(t, "domain", response.ObjectClassName)
	assert.NotEmpty(t, response.Nameservers)
	assert.NotEmpty(t, response.Events)
	assert.NotEmpty(t, response.Entities)

	// Check that nameservers are properly parsed
	for _, ns := range response.Nameservers {
		assert.Equal(t, "nameserver", ns.ObjectClassName)
		assert.NotEmpty(t, ns.LdhName)
	}
}

func TestRDAPIPParsing(t *testing.T) {
	client := NewRDAPClient()
	response, err := client.QueryRDAP("8.8.8.8")
	assert.Nil(t, err)

	// Check IP-specific fields
	assert.Equal(t, "ip network", response.ObjectClassName)
	assert.Equal(t, "8.8.8.8", response.StartAddress)
	assert.Equal(t, "8.8.8.8", response.EndAddress)
	assert.Equal(t, "v4", response.IPVersion)
	assert.NotEmpty(t, response.RawWhois)
}

func TestRDAPASNParsing(t *testing.T) {
	client := NewRDAPClient()
	response, err := client.QueryRDAP("AS15169")
	assert.Nil(t, err)

	// Check ASN-specific fields
	assert.Equal(t, "autnum", response.ObjectClassName)
	assert.Equal(t, "AS15169", response.Autnum)
	assert.NotEmpty(t, response.RawWhois)
}

func TestRDAPHelperFunctions(t *testing.T) {
	// Test domain detection
	assert.True(t, isDomain("example.com"))
	assert.True(t, isDomain("egger.ru"))
	assert.False(t, isDomain("8.8.8.8"))
	assert.False(t, isDomain("AS15169"))

	// Test IP detection
	assert.True(t, isIP("8.8.8.8"))
	assert.True(t, isIP("2001:db8::1"))
	assert.False(t, isIP("example.com"))
	assert.False(t, isIP("AS15169"))

	// Test ASN detection
	assert.True(t, isASN("AS15169"))
	assert.True(t, isASN("15169"))
	assert.False(t, isASN("example.com"))
	assert.False(t, isASN("8.8.8.8"))

	// Test IP version detection
	assert.Equal(t, "v4", getIPVersion("8.8.8.8"))
	assert.Equal(t, "v6", getIPVersion("2001:db8::1"))
}

func TestRDAPErrorHandling(t *testing.T) {
	// Test with invalid domain
	_, err := QueryRDAP("")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "failed to query WHOIS")
}

func TestRDAPNotices(t *testing.T) {
	response, err := QueryRDAP("egger.ru")
	assert.Nil(t, err)
	assert.NotEmpty(t, response.Notices)

	// Check that notices are properly set
	notice := response.Notices[0]
	assert.Equal(t, "Terms of Service", notice.Title)
	assert.Equal(t, "result set truncated due to authorization", notice.Type)
	assert.NotEmpty(t, notice.Description)
}
