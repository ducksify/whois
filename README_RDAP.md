# RDAP Wrapper for WHOIS Package

This package provides an RDAP (Registration Data Access Protocol) wrapper for the whois package, converting raw WHOIS data into structured JSON format following the RDAP specification (RFC 7483).

## What is RDAP?

RDAP (Registration Data Access Protocol) is a modern replacement for WHOIS that provides:
- **Structured JSON responses** instead of plain text
- **Standardized data formats** across different registries
- **Better internationalization support** with Unicode handling
- **More detailed metadata** including conformance information
- **Consistent error handling** with standardized error codes

## Features

### ✅ Complete RDAP Implementation
- Full RFC 7483 compliance
- Support for all RDAP object classes (domain, ip network, autnum)
- Standard RDAP response structure with conformance levels

### ✅ Multiple Query Types
- **Domains**: `example.com`, `egger.ru`
- **IP Addresses**: `8.8.8.8`, `2001:db8::1`
- **ASNs**: `AS15169`, `15169`

### ✅ Rich Data Structure
- **Events**: Registration, expiration, and modification dates
- **Entities**: Registrars, contacts, and organizations
- **Nameservers**: Complete nameserver information for domains
- **Status**: Object status and flags
- **Raw Data**: Original WHOIS data preserved
- **Parsed Data**: Structured key-value pairs

### ✅ Easy Integration
- Drop-in replacement for existing WHOIS queries
- Compatible with existing whois package
- Minimal code changes required

## Quick Start

### Basic Usage

```go
import "github.com/ducksify/whois"

// Query a domain and get RDAP response
rdapResponse, err := whois.QueryRDAP("egger.ru")
if err != nil {
    log.Fatal(err)
}

// Convert to JSON
jsonData, err := rdapResponse.ToJSON()
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jsonData))
```

### Custom Client

```go
// Create custom RDAP client with timeout
rdapClient := whois.NewRDAPClient()
rdapClient.SetTimeout(30 * time.Second)

// Query with custom client
response, err := rdapClient.QueryRDAP("8.8.8.8")
if err != nil {
    log.Fatal(err)
}

// Get JSON string
jsonString, err := response.ToJSONString()
if err != nil {
    log.Fatal(err)
}
fmt.Println(jsonString)
```

## API Reference

### Functions

#### `QueryRDAP(query string) (*RDAPResponse, error)`
Convenience function that uses the default client to query RDAP data.

#### `NewRDAPClient() *RDAPClient`
Creates a new RDAP client with default settings.

### Methods

#### `(*RDAPClient) QueryRDAP(query string) (*RDAPResponse, error)`
Performs an RDAP query and returns structured RDAP response.

#### `(*RDAPResponse) ToJSON() ([]byte, error)`
Converts the RDAP response to JSON bytes.

#### `(*RDAPResponse) ToJSONString() (string, error)`
Converts the RDAP response to JSON string.

## Response Structure

### RDAPResponse
```go
type RDAPResponse struct {
    RdapConformance []string                 `json:"rdapConformance"`
    Notices         []RDAPNotice             `json:"notices,omitempty"`
    Handle          string                   `json:"handle,omitempty"`
    StartAddress    string                   `json:"startAddress,omitempty"`
    EndAddress      string                   `json:"endAddress,omitempty"`
    IPVersion       string                   `json:"ipVersion,omitempty"`
    Name            string                   `json:"name,omitempty"`
    Type            string                   `json:"type,omitempty"`
    Entities        []RDAPEntity             `json:"entities,omitempty"`
    Events          []RDAPEvent              `json:"events,omitempty"`
    Links           []RDAPLink               `json:"links,omitempty"`
    Port43          string                   `json:"port43,omitempty"`
    Status          []string                 `json:"status,omitempty"`
    ObjectClassName string                   `json:"objectClassName"`
    LdhName         string                   `json:"ldhName,omitempty"`
    UnicodeName     string                   `json:"unicodeName,omitempty"`
    Nameservers     []RDAPNameserver         `json:"nameservers,omitempty"`
    SecureDNS       *RDAPSecureDNS           `json:"secureDNS,omitempty"`
    Network         *RDAPNetwork             `json:"network,omitempty"`
    Autnum          string                   `json:"autnum,omitempty"`
    AsEventActor    string                   `json:"asEventActor,omitempty"`
    Remarks         []RDAPRemark             `json:"remarks,omitempty"`
    Lang            string                   `json:"lang,omitempty"`
    VCardArray      []interface{}            `json:"vcardArray,omitempty"`
    Roles           []string                 `json:"roles,omitempty"`
    PublicIds       []RDAPPublicID           `json:"publicIds,omitempty"`
    Addresses       []RDAPAddress            `json:"addresses,omitempty"`
    PhoneNumbers    []RDAPPhoneNumber        `json:"phoneNumbers,omitempty"`
    EmailAddresses  []RDAPEmailAddress       `json:"emailAddresses,omitempty"`
    RawWhois        string                   `json:"rawWhois,omitempty"`
    WhoisParsed     map[string]interface{}   `json:"whoisParsed,omitempty"`
}
```

## Examples

### Domain Query

```json
{
  "rdapConformance": ["rdap_level_0"],
  "objectClassName": "domain",
  "ldhName": "egger.ru",
  "unicodeName": "egger.ru",
  "nameservers": [
    {
      "objectClassName": "nameserver",
      "ldhName": "ns1.dns.millenniumarts.net."
    }
  ],
  "events": [
    {
      "eventAction": "registration",
      "eventDate": "2001-02-19T21:00:00Z"
    },
    {
      "eventAction": "expiration",
      "eventDate": "2026-02-20T21:00Z"
    }
  ],
  "entities": [
    {
      "objectClassName": "entity",
      "handle": "RU-CENTER-RU",
      "roles": ["registrar"]
    }
  ],
  "rawWhois": "original WHOIS data...",
  "whoisParsed": {
    "Domain Name": "EGGER.RU",
    "Registrar": "RU-CENTER-RU",
    "Created": "2001-02-19T21:00:00Z"
  }
}
```

### IP Address Query

```json
{
  "rdapConformance": ["rdap_level_0"],
  "objectClassName": "ip network",
  "startAddress": "8.8.8.8",
  "endAddress": "8.8.8.8",
  "ipVersion": "v4",
  "name": "GOGL",
  "network": {
    "objectClassName": "ip network",
    "country": "US"
  },
  "events": [
    {
      "eventAction": "registration",
      "eventDate": "2000-03-30"
    }
  ]
}
```

### ASN Query

```json
{
  "rdapConformance": ["rdap_level_0"],
  "objectClassName": "autnum",
  "autnum": "AS15169",
  "name": "GOOGLE",
  "events": [
    {
      "eventAction": "registration",
      "eventDate": "2000-03-30"
    }
  ]
}
```

## Running Examples

### Basic RDAP Example

```bash
go run cmd/rdap_example/main.go
```

### Original WHOIS Example

```bash
go run cmd/egger_example/main.go
```

## Testing

Run the RDAP tests:
```bash
go test -v -run TestRDAP
```

Run all tests:
```bash
go test -v
```

## Benefits Over Raw WHOIS

### 1. **Structured Data**
- No need to parse text manually
- Consistent field names across registries
- Type-safe access to data

### 2. **Rich Metadata**
- Registration and expiration events
- Entity relationships (registrars, contacts)
- Status information
- Nameserver details

### 3. **Standard Compliance**
- RFC 7483 compliant
- Interoperable with other RDAP clients
- Future-proof format

### 4. **Better Error Handling**
- Structured error responses
- Consistent error codes
- Detailed error messages

### 5. **Internationalization**
- Unicode support
- Multi-language descriptions
- Proper character encoding

## Migration from WHOIS

### Before (Raw WHOIS)
```go
result, err := whois.Whois("egger.ru")
if err != nil {
    log.Fatal(err)
}
// Need to parse text manually
lines := strings.Split(result, "\n")
// Extract fields manually...
```

### After (RDAP)
```go
response, err := whois.QueryRDAP("egger.ru")
if err != nil {
    log.Fatal(err)
}
// Access structured data directly
fmt.Println(response.Name)
fmt.Println(response.Events[0].EventDate)
fmt.Println(response.Entities[0].Handle)
```

## Requirements

- Go 1.24 or later
- Internet connection to query WHOIS servers
- No additional dependencies beyond the base whois package

## License

Licensed under the Apache License 2.0 - see the LICENSE file for details.
