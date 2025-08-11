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
 * RDAP wrapper for whois package
 */

package whois

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// RDAPResponse represents the standard RDAP response structure
type RDAPResponse struct {
	RdapConformance []string               `json:"rdapConformance"`
	Notices         []RDAPNotice           `json:"notices,omitempty"`
	Handle          string                 `json:"handle,omitempty"`
	StartAddress    string                 `json:"startAddress,omitempty"`
	EndAddress      string                 `json:"endAddress,omitempty"`
	IPVersion       string                 `json:"ipVersion,omitempty"`
	Name            string                 `json:"name,omitempty"`
	Type            string                 `json:"type,omitempty"`
	Entities        []RDAPEntity           `json:"entities,omitempty"`
	Events          []RDAPEvent            `json:"events,omitempty"`
	Links           []RDAPLink             `json:"links,omitempty"`
	Port43          string                 `json:"port43,omitempty"`
	Status          []string               `json:"status,omitempty"`
	ObjectClassName string                 `json:"objectClassName"`
	LdhName         string                 `json:"ldhName,omitempty"`
	UnicodeName     string                 `json:"unicodeName,omitempty"`
	Nameservers     []RDAPNameserver       `json:"nameservers,omitempty"`
	SecureDNS       *RDAPSecureDNS         `json:"secureDNS,omitempty"`
	Network         *RDAPNetwork           `json:"network,omitempty"`
	Autnum          string                 `json:"autnum,omitempty"`
	AsEventActor    string                 `json:"asEventActor,omitempty"`
	Remarks         []RDAPRemark           `json:"remarks,omitempty"`
	Lang            string                 `json:"lang,omitempty"`
	VCardArray      []interface{}          `json:"vcardArray,omitempty"`
	Roles           []string               `json:"roles,omitempty"`
	PublicIds       []RDAPPublicID         `json:"publicIds,omitempty"`
	Addresses       []RDAPAddress          `json:"addresses,omitempty"`
	PhoneNumbers    []RDAPPhoneNumber      `json:"phoneNumbers,omitempty"`
	EmailAddresses  []RDAPEmailAddress     `json:"emailAddresses,omitempty"`
	RawWhois        string                 `json:"rawWhois,omitempty"`
	WhoisParsed     map[string]interface{} `json:"whoisParsed,omitempty"`
}

// RDAPNotice represents RDAP notices
type RDAPNotice struct {
	Title       string     `json:"title"`
	Type        string     `json:"type"`
	Description []string   `json:"description"`
	Links       []RDAPLink `json:"links,omitempty"`
}

// RDAPEntity represents RDAP entities
type RDAPEntity struct {
	ObjectClassName string             `json:"objectClassName"`
	Handle          string             `json:"handle,omitempty"`
	VCardArray      []interface{}      `json:"vcardArray,omitempty"`
	Roles           []string           `json:"roles,omitempty"`
	PublicIds       []RDAPPublicID     `json:"publicIds,omitempty"`
	Entities        []RDAPEntity       `json:"entities,omitempty"`
	Remarks         []RDAPRemark       `json:"remarks,omitempty"`
	Links           []RDAPLink         `json:"links,omitempty"`
	Events          []RDAPEvent        `json:"events,omitempty"`
	Addresses       []RDAPAddress      `json:"addresses,omitempty"`
	PhoneNumbers    []RDAPPhoneNumber  `json:"phoneNumbers,omitempty"`
	EmailAddresses  []RDAPEmailAddress `json:"emailAddresses,omitempty"`
}

// RDAPEvent represents RDAP events
type RDAPEvent struct {
	EventAction string     `json:"eventAction"`
	EventActor  string     `json:"eventActor,omitempty"`
	EventDate   string     `json:"eventDate"`
	Links       []RDAPLink `json:"links,omitempty"`
}

// RDAPLink represents RDAP links
type RDAPLink struct {
	Value string `json:"value"`
	Rel   string `json:"rel"`
	Href  string `json:"href"`
	Type  string `json:"type,omitempty"`
}

// RDAPNameserver represents RDAP nameservers
type RDAPNameserver struct {
	ObjectClassName string      `json:"objectClassName"`
	LdhName         string      `json:"ldhName"`
	UnicodeName     string      `json:"unicodeName,omitempty"`
	Handle          string      `json:"handle,omitempty"`
	Status          []string    `json:"status,omitempty"`
	Links           []RDAPLink  `json:"links,omitempty"`
	Events          []RDAPEvent `json:"events,omitempty"`
	IPAddresses     *RDAPIPs    `json:"ipAddresses,omitempty"`
}

// RDAPIPs represents IP addresses in RDAP
type RDAPIPs struct {
	V4 []string `json:"v4,omitempty"`
	V6 []string `json:"v6,omitempty"`
}

// RDAPSecureDNS represents secure DNS information
type RDAPSecureDNS struct {
	ZoneSigned       bool     `json:"zoneSigned"`
	DelegationSigned bool     `json:"delegationSigned"`
	MaxSigLife       int      `json:"maxSigLife,omitempty"`
	DSData           []RDAPDS `json:"dsData,omitempty"`
}

// RDAPDS represents DS records
type RDAPDS struct {
	KeyTag     int    `json:"keyTag"`
	Algorithm  int    `json:"algorithm"`
	DigestType int    `json:"digestType"`
	Digest     string `json:"digest"`
}

// RDAPNetwork represents network information
type RDAPNetwork struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	StartAddress    string       `json:"startAddress"`
	EndAddress      string       `json:"endAddress"`
	IPVersion       string       `json:"ipVersion"`
	Name            string       `json:"name,omitempty"`
	Type            string       `json:"type,omitempty"`
	Country         string       `json:"country,omitempty"`
	ParentHandle    string       `json:"parentHandle,omitempty"`
	Status          []string     `json:"status,omitempty"`
	Entities        []RDAPEntity `json:"entities,omitempty"`
	Events          []RDAPEvent  `json:"events,omitempty"`
	Links           []RDAPLink   `json:"links,omitempty"`
	Remarks         []RDAPRemark `json:"remarks,omitempty"`
}

// RDAPRemark represents RDAP remarks
type RDAPRemark struct {
	Title       string     `json:"title,omitempty"`
	Type        string     `json:"type,omitempty"`
	Description []string   `json:"description"`
	Links       []RDAPLink `json:"links,omitempty"`
}

// RDAPPublicID represents public identifiers
type RDAPPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// RDAPAddress represents addresses
type RDAPAddress struct {
	Type            string   `json:"type,omitempty"`
	PostOfficeBox   []string `json:"postOfficeBox,omitempty"`
	ExtendedAddress []string `json:"extendedAddress,omitempty"`
	StreetAddress   []string `json:"streetAddress,omitempty"`
	Locality        []string `json:"locality,omitempty"`
	Region          []string `json:"region,omitempty"`
	PostalCode      []string `json:"postalCode,omitempty"`
	CountryName     []string `json:"countryName,omitempty"`
}

// RDAPPhoneNumber represents phone numbers
type RDAPPhoneNumber struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

// RDAPEmailAddress represents email addresses
type RDAPEmailAddress struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

// RDAPClient represents an RDAP client
type RDAPClient struct {
	*Client
	httpClient *http.Client
}

// NewRDAPClient creates a new RDAP client
func NewRDAPClient() *RDAPClient {
	return &RDAPClient{
		Client: NewClient(),
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// QueryRDAP performs an RDAP query and returns structured RDAP response
func (rc *RDAPClient) QueryRDAP(query string) (*RDAPResponse, error) {
	// First get the raw WHOIS data
	whoisData, err := rc.Whois(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query WHOIS: %w", err)
	}

	// Convert WHOIS data to RDAP format
	rdapResponse, err := rc.convertWhoisToRDAP(query, whoisData)
	if err != nil {
		return nil, fmt.Errorf("failed to convert WHOIS to RDAP: %w", err)
	}

	return rdapResponse, nil
}

// QueryRDAP is a convenience function using the default client
func QueryRDAP(query string) (*RDAPResponse, error) {
	client := NewRDAPClient()
	return client.QueryRDAP(query)
}

// convertWhoisToRDAP converts WHOIS data to RDAP format
func (rc *RDAPClient) convertWhoisToRDAP(query, whoisData string) (*RDAPResponse, error) {
	response := &RDAPResponse{
		RdapConformance: []string{"rdap_level_0"},
		RawWhois:        whoisData,
		WhoisParsed:     make(map[string]interface{}),
	}

	// Determine the type of query and set object class
	if isDomain(query) {
		response.ObjectClassName = "domain"
		response.LdhName = strings.ToLower(query)
		response.UnicodeName = query
		rc.parseDomainWhois(response, whoisData)
	} else if isIP(query) {
		response.ObjectClassName = "ip network"
		response.StartAddress = query
		response.EndAddress = query
		response.IPVersion = getIPVersion(query)
		rc.parseIPWhois(response, whoisData)
	} else if isASN(query) {
		response.ObjectClassName = "autnum"
		response.Autnum = query
		rc.parseASNWhois(response, whoisData)
	}

	// Add standard notices
	response.Notices = append(response.Notices, RDAPNotice{
		Title:       "Terms of Service",
		Type:        "result set truncated due to authorization",
		Description: []string{"This response has been truncated due to authorization."},
	})

	return response, nil
}

// parseDomainWhois parses domain WHOIS data into RDAP format
func (rc *RDAPClient) parseDomainWhois(response *RDAPResponse, whoisData string) {
	lines := strings.Split(whoisData, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		response.WhoisParsed[key] = value

		switch strings.ToLower(key) {
		case "domain name":
			response.Name = value
		case "registrar":
			response.Entities = append(response.Entities, RDAPEntity{
				ObjectClassName: "entity",
				Handle:          value,
				Roles:           []string{"registrar"},
			})
		case "created":
			response.Events = append(response.Events, RDAPEvent{
				EventAction: "registration",
				EventDate:   value,
			})
		case "paid-till", "expires":
			response.Events = append(response.Events, RDAPEvent{
				EventAction: "expiration",
				EventDate:   value,
			})
		case "updated":
			response.Events = append(response.Events, RDAPEvent{
				EventAction: "last changed",
				EventDate:   value,
			})
		case "nserver":
			response.Nameservers = append(response.Nameservers, RDAPNameserver{
				ObjectClassName: "nameserver",
				LdhName:         value,
			})
		case "status":
			response.Status = append(response.Status, value)
		}
	}
}

// parseIPWhois parses IP WHOIS data into RDAP format
func (rc *RDAPClient) parseIPWhois(response *RDAPResponse, whoisData string) {
	lines := strings.Split(whoisData, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		response.WhoisParsed[key] = value

		switch strings.ToLower(key) {
		case "netname", "network name":
			response.Name = value
		case "descr", "description":
			if response.Remarks == nil {
				response.Remarks = []RDAPRemark{}
			}
			response.Remarks = append(response.Remarks, RDAPRemark{
				Description: []string{value},
			})
		case "country":
			response.Network = &RDAPNetwork{
				ObjectClassName: "ip network",
				Country:         value,
			}
		case "created":
			response.Events = append(response.Events, RDAPEvent{
				EventAction: "registration",
				EventDate:   value,
			})
		case "last-modified":
			response.Events = append(response.Events, RDAPEvent{
				EventAction: "last changed",
				EventDate:   value,
			})
		}
	}
}

// parseASNWhois parses ASN WHOIS data into RDAP format
func (rc *RDAPClient) parseASNWhois(response *RDAPResponse, whoisData string) {
	lines := strings.Split(whoisData, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		response.WhoisParsed[key] = value

		switch strings.ToLower(key) {
		case "as-name", "aut-num":
			response.Name = value
		case "descr", "description":
			if response.Remarks == nil {
				response.Remarks = []RDAPRemark{}
			}
			response.Remarks = append(response.Remarks, RDAPRemark{
				Description: []string{value},
			})
		case "created":
			response.Events = append(response.Events, RDAPEvent{
				EventAction: "registration",
				EventDate:   value,
			})
		case "last-modified":
			response.Events = append(response.Events, RDAPEvent{
				EventAction: "last changed",
				EventDate:   value,
			})
		}
	}
}

// Helper functions
func isDomain(query string) bool {
	return strings.Contains(query, ".") && !isIP(query)
}

func isIP(query string) bool {
	ipRegex := regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$`)
	return ipRegex.MatchString(query)
}

func isASN(query string) bool {
	return IsASN(query)
}

func getIPVersion(query string) string {
	if strings.Contains(query, ":") {
		return "v6"
	}
	return "v4"
}

// ToJSON converts the RDAP response to JSON
func (r *RDAPResponse) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

