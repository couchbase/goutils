// Copyright 2016-Present Couchbase, Inc.
//
// Use of this software is governed by the Business Source License included in
// the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
// file, in accordance with the Business Source License, use of this software
// will be governed by the Apache License, Version 2.0, included in the file
// licenses/APL2.txt.
package audit

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/couchbase/cbauth"
	"github.com/couchbase/go-couchbase"
	mc "github.com/couchbase/gomemcached"
	mcc "github.com/couchbase/gomemcached/client"

	log "github.com/couchbase/clog"
)

// opcode for memcached audit command
var AuditPutCommandCode = mc.CommandCode(0x27)

// write timeout
var WriteTimeout = 1000 * time.Millisecond

// read timeout
var ReadTimeout = 1000 * time.Millisecond
var PoolClients = 5

type GenericFields struct {
	Timestamp  string     `json:"timestamp"`
	RealUserid RealUserId `json:"real_userid"`
}

type CommonAuditFields struct {
	GenericFields

	Local  *addressFields `json:"local,omitempty"`
	Remote *addressFields `json:"remote,omitempty"`
}

type addressFields struct {
	Ip   string `json:"ip"`
	Port string `json:"port,omitempty"`
}

type RealUserId struct {
	Domain   string `json:"domain"`
	Username string `json:"user"`
}

type AuditSvc struct {
	uri       string
	u         string
	p         string
	localhost string
	kvaddr    string
	client    chan *mcc.Client

	m sync.Mutex // Protects the fields that follow.

	initialized bool
}

func NewAuditSvc(uri string) (*AuditSvc, error) {
	parsedUri, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	u, p, err := cbauth.GetHTTPServiceAuth(parsedUri.Host)
	if err != nil {
		return nil, err
	}
	localhost, _, _ := net.SplitHostPort(parsedUri.Host)
	service := &AuditSvc{
		uri:         uri,
		u:           u,
		p:           p,
		localhost:   localhost,
		initialized: false,
		client:      make(chan *mcc.Client, PoolClients),
	}
	// Attempt to initialize the service here. No need to check for
	// the err returned as if the service initialization were to
	// fail because of the server not being ready yet, we will do
	// this lazily when the Write API is invoked.
	service.init()
	log.Printf("audit: created new audit service")
	return service, nil
}

func (service *AuditSvc) Write(eventId uint32, event interface{}) error {
	err := service.init()
	if err != nil {
		return err
	}
	client, err := service.getClient()
	if err != nil {
		return err
	}
	if !client.IsHealthy() {
		log.Printf("audit: Client found unhealthy. Creating new client.")
		err = client.Close()
		if err != nil {
			log.Printf("audit: unable to close unhealthy connection: %v", err)
		}

		newClient, err := GetNewConnection(service.kvaddr)
		if err != nil {
			return fmt.Errorf("audit: unable to create new client: %v", err)
		}
		client = newClient
	}

	defer service.releaseClient(client)
	return service.writeOnClient(client, eventId, event)
}

// Get a new connection that is not part of the general pool.
// The caller is responsible for its management.
func (service *AuditSvc) GetNonPoolClient() (*mcc.Client, error) {
	client, err := GetNewConnection(service.kvaddr)
	return client, err
}

func (service *AuditSvc) WriteUsingNonPoolClient(client *mcc.Client, eventId uint32,
	event interface{}) error {
	return service.writeOnClient(client, eventId, event)
}

func (service *AuditSvc) writeOnClient(client *mcc.Client, eventId uint32,
	event interface{}) error {
	req, err := composeAuditRequest(eventId, event)
	if err != nil {
		return err
	}

	if err := client.TransmitWithDeadline(req, time.Now().Add(WriteTimeout)); err != nil {
		return err
	}

	res, err := client.ReceiveWithDeadline(time.Now().Add(ReadTimeout))

	if err != nil {
		return err
	} else if res.Opcode != AuditPutCommandCode {
		return errors.New(fmt.Sprintf("unexpected #opcode %v", res.Opcode))
	} else if req.Opaque != res.Opaque {
		return errors.New(fmt.Sprintf("opaque mismatch, %v over %v",
			req.Opaque, res.Opaque))
	} else if res.Status != mc.SUCCESS {
		return errors.New(fmt.Sprintf("unsuccessful status = %v", res.Status))
	}

	return nil
}

func composeAuditRequest(eventId uint32, event interface{}) (
	*mc.MCRequest, error) {
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}

	req := &mc.MCRequest{
		Opcode: AuditPutCommandCode}

	req.Extras = make([]byte, 4)
	binary.BigEndian.PutUint32(req.Extras[:4], eventId)

	req.Body = eventBytes

	req.Opaque = eventId
	return req, nil
}

func (service *AuditSvc) init() error {
	service.m.Lock()
	defer service.m.Unlock()
	if !service.initialized {
		client, err := couchbase.ConnectWithAuthCreds(service.uri,
			service.u, service.p)
		if err != nil {
			return fmt.Errorf("audit: error in connecting to url %s: %v", service.uri, err)
		}
		pool, err := client.GetPool("default")
		if err != nil {
			return fmt.Errorf("audit: error in connecting to default pool: %v", err)
		}
		defer pool.Close()
		for _, p := range pool.Nodes {
			if p.ThisNode {
				port, ok := p.Ports["direct"]
				if !ok {
					return fmt.Errorf("Error in getting memcached port")
				}

				var h string
				if service.localhost != "" {
					h = service.localhost
				} else {
					h, _, err = net.SplitHostPort(p.Hostname)
					if err != nil || len(h) < 1 {
						return fmt.Errorf("Invalid host string")
					}
				}
				service.kvaddr = net.JoinHostPort(h, strconv.Itoa(port))
				break
			}
		}
		if service.kvaddr == "" {
			return fmt.Errorf("Error in getting port")
		}
		for i := len(service.client); i < PoolClients; i++ {
			c, err := GetNewConnection(service.kvaddr)
			if err != nil {
				return fmt.Errorf("audit: Unable to get connection: %v", err)
			}
			service.client <- c
		}
		service.initialized = true
	}
	return nil
}

func (service *AuditSvc) getClient() (*mcc.Client, error) {
	return <-service.client, nil
}

func (service *AuditSvc) releaseClient(client *mcc.Client) error {
	service.client <- client
	return nil
}

func GetAuditBasicFields(req *http.Request) GenericFields {
	uid := getRealUserIdFromRequest(req)
	t := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	return GenericFields{t, *uid}
}

/*
The following function should be used by go services to log audit-log information common across all services.
Presently, timestamp, user, local/remote endpoint ip-address have been taken care of.

Logical fields to be added here in future would be:
additional node-level information, if any.
cluster-name
etc.

W.r.t the "local" address, i.e., the ip-address / port the service is listening on for connection requests:
The ticket https://issues.couchbase.com/browse/MB-40204 has sample code provided by James Lee / Daniel Owen on
how to extract the local address information for go services.

go services that do not setup a ConnContext function in httpServer will get a different behavior wherein the
"local" address information is extracted from the HttpRequest.Host header.
*/

func GetCommonAuditFields(req *http.Request) CommonAuditFields {

	gf := GetAuditBasicFields(req)

	var l string

	var portValidator func(port string) bool

	if req.Context().Value("conn") != nil {

		conn := req.Context().Value("conn").(net.Conn)
		l = conn.LocalAddr().String()

	} else {

		l = req.Host

		portValidator = func(port string) bool {
			_, err := strconv.Atoi(port)
			if err != nil {
				return true
			}

			return false
		}
	}

	// remote address always comes out from the connection; no validation necessary
	remote := parseAddress(req.RemoteAddr, nil)

	// local can come either out of the connection context, or from HttpRequest.Host header (untrusted).
	// Need to validate if we try extract the address from an untrusted source.
	local := parseAddress(l, portValidator)

	return CommonAuditFields{gf, local, remote}
}

func parseAddress(addr string, portValidator func(port string) bool) *addressFields {
	if addr == "" {
		return nil
	}

	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		// No host:port separator. Put everything in Ip field.
		return &addressFields{Ip: addr}
	}

	host := addr[:lastColon]
	port := addr[lastColon+1:] // Not including the colon itself.

	if portValidator != nil {
		if invalidPort := portValidator(port); invalidPort {
			log.Printf("Auditing: unable to parse port %s of address %s", port, addr)
			return &addressFields{Ip: addr}
		}
	}

	return &addressFields{Ip: host, Port: port}
}

func getRealUserIdFromRequest(request *http.Request) *RealUserId {
	creds, err := cbauth.AuthWebCreds(request)
	if err != nil {
		log.Printf("audit: unable to get real userid from request: %v", err)

		// put unknown user in the audit log.
		return &RealUserId{"local", "unknown"}
	}

	return &RealUserId{creds.Domain(), creds.Name()}
}

func GetNewConnection(kvAddr string) (*mcc.Client, error) {
	c, err := mcc.Connect("tcp", kvAddr)
	if err != nil {
		return nil, fmt.Errorf("audit: Error in connection to"+
			" memcached: %v", err)
	}
	u, p, err := cbauth.GetMemcachedServiceAuth(kvAddr)
	if err != nil {
		return nil, fmt.Errorf("audit: Error in getting auth for"+
			" memcached: %v", err)
	}
	_, err = c.Auth(u, p)
	if err != nil {
		return nil, fmt.Errorf("audit: Error in auth: %v", err)
	}
	return c, nil
}
