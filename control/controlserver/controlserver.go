package controlserver

import (
	"errors"
	"github.com/google/uuid"
	"github.com/tailscale/wireguard-go/wgcfg"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"tailscale.com/derp/derpmap"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"time"
)

type Host struct {
	Node         *tailcfg.Node
	DERPMap      *tailcfg.DERPMap
	Peers        []tailcfg.NodeID
	PeersChanged []tailcfg.NodeID
	PeersRemoved []tailcfg.NodeID
}

type ControlServer struct {
	privateKey key.Private
	publicKey  key.Public
	logf       logger.Logf
	metaCert   []byte // the encoded x509 cert to send after LetsEncrypt cert+intermediate
	groups     map[tailcfg.GroupID]*tailcfg.Group
	users      map[tailcfg.UserID]*tailcfg.User
	hosts      map[tailcfg.NodeID]*Host
	knownHost  map[tailcfg.MachineKey]tailcfg.NodeID
}

var matchLoginRequest = regexp.MustCompile(`machine/`)
var matchPollMapRequest = regexp.MustCompile(`machine/.*/map`)

func NewServer(privateKey key.Private, logf logger.Logf) *ControlServer {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	s := &ControlServer{
		privateKey: privateKey,
		publicKey:  privateKey.Public(),
		logf:       logf,
		groups:     map[tailcfg.GroupID]*tailcfg.Group{},
		users:      map[tailcfg.UserID]*tailcfg.User{},
		hosts:      map[tailcfg.NodeID]*Host{},
	}

	return s
}

func encode(v interface{}, clientKey *wgcfg.Key, mkey *key.Private) ([]byte, error) {
	return nil, nil
}

func decode(req *http.Request, v interface{}, clientKey *wgcfg.Key, mkey *key.Private) error {
	return nil
}

func Router(s *ControlServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case matchLoginRequest.MatchString(r.URL.Path):
			s.loginHandler(w, r)
		case matchPollMapRequest.MatchString(r.URL.Path):
			s.pollNetMapHandler(w, r)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			io.WriteString(w, `<html><body>
				<h1>ControlServer</h1>
				<p>
				  This is a
				  <a href="https://tailscale.com/">Tailscale</a>
				  <a>ControlServer</a>
				  server.
				</p>`)
		}
	})
}

func matchClientMachineKey(reg *regexp.Regexp, url string) (wgcfg.Key, error) {
	var err error
	match := reg.FindStringSubmatch(url)
	if len(match) <= 1 {
		err = errors.New("No clientKey found.")
	}
	clientKey, err := wgcfg.ParseHexKey(match[1])
	return clientKey, err
}

func (s *ControlServer) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		io.WriteString(w, "Method not allowed")
		return
	}
	reg := regexp.MustCompile(`machine/(.*)`)
	clientMachineKey, err := matchClientMachineKey(reg, r.URL.Path)
	if err != nil {
		panic("Parse ClientKey Failure.")
	}
	request := tailcfg.RegisterRequest{}
	if err := decode(r, &request, &clientMachineKey, &s.privateKey); err != nil {
		panic("Decode login request failure")
	}

	// TODO: implement login logic

	res := tailcfg.RegisterResponse{
		User:              tailcfg.User{},
		Login:             tailcfg.Login{},
		NodeKeyExpired:    false,
		MachineAuthorized: false,
		AuthURL:           "",
	}

	resBody, err := encode(res, &clientMachineKey, &s.privateKey)
	if err != nil {
		panic("Encode login response failure.")
	}

	w.Write(resBody)
}

func idGenerator() int64 {
	u := uuid.New().ID()
	return int64(u)
}

func (s *ControlServer) addNewHost(node *tailcfg.Node, derpMap *tailcfg.DERPMap,
	knownHost map[tailcfg.MachineKey]tailcfg.NodeID, machineKey tailcfg.MachineKey) Host {
	knownHostCopy := knownHost
	delete(knownHostCopy, node.Machine)

	knownNodeId := make([]tailcfg.NodeID, 0, len(knownHostCopy))

	for _, v := range knownHostCopy {
		knownNodeId = append(knownNodeId, v)
	}

	host := Host{
		Node:         node,
		DERPMap:      derpMap,
		Peers:        knownNodeId,
		PeersChanged: nil,
		PeersRemoved: nil,
	}

	s.knownHost[machineKey] = node.ID
	s.hosts[node.ID] = &host

	return host
}

func (s *ControlServer) pollNetMapHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		io.WriteString(w, "Method not allowed")
		return
	}
	reg := regexp.MustCompile(`machine/(.*)/map`)
	clientMachineKey, err := matchClientMachineKey(reg, r.URL.Path)
	if err != nil {
		panic("Parse ClientKey Failure.")
	}

	pollRequest := tailcfg.MapRequest{}
	if err := decode(r, &pollRequest, &clientMachineKey, &s.privateKey); err != nil {
		panic("Decode pollNetMap request failure")
	}

	// TODO: implement real logic
	resp := tailcfg.MapResponse{
		KeepAlive:    pollRequest.KeepAlive,
		Node:         nil,
		DERPMap:      nil,
		Peers:        nil,
		PeersChanged: nil,
		PeersRemoved: nil,
		DNS:          nil,
		SearchPaths:  nil,
		DNSConfig:    tailcfg.DNSConfig{},
		Domain:       "",
		PacketFilter: nil,
		UserProfiles: nil,
		Roles:        nil,
		Debug:        nil,
	}

	if nodeId, ok := s.knownHost[tailcfg.MachineKey(clientMachineKey)]; ok {
		host := s.hosts[nodeId]

		hostChanged := false

		if pollRequest.NodeKey != host.Node.Key {
			host.Node.Key = pollRequest.NodeKey
			hostChanged = true
		}

		if pollRequest.DiscoKey != host.Node.DiscoKey {
			host.Node.DiscoKey = pollRequest.DiscoKey
			hostChanged = true
		}

		if !reflect.DeepEqual(pollRequest.Endpoints, host.Node.Endpoints) {
			host.Node.Endpoints = pollRequest.Endpoints
			hostChanged = true
		}

		if !pollRequest.Hostinfo.Equal(&host.Node.Hostinfo) {
			// update node info
			host.Node.AllowedIPs = pollRequest.Hostinfo.RoutableIPs
			host.Node.DERP = strconv.Itoa(pollRequest.Hostinfo.NetInfo.PreferredDERP)
			host.Node.Hostinfo = *pollRequest.Hostinfo
			hostChanged = true
		}

		if hostChanged {
			// notify other hosts that their peer has changed
		}

		host.Node.KeepAlive = pollRequest.KeepAlive

		resp.Node = host.Node
		resp.DERPMap = host.DERPMap

		peersChanged := []*tailcfg.Node{}
		for _, nodeId := range host.PeersChanged {
			peersChanged = append(peersChanged, s.hosts[nodeId].Node)
		}
		resp.PeersChanged = peersChanged
		// TODO: add peer remove logic
		resp.PeersRemoved = host.PeersRemoved
	} else {
		nodeId := tailcfg.NodeID(idGenerator())
		node := tailcfg.Node{
			ID:                nodeId,
			Name:              "",
			User:              0,
			Key:               pollRequest.NodeKey,
			KeyExpiry:         time.Now().Add(time.Hour * 8760),
			Machine:           tailcfg.MachineKey(clientMachineKey),
			DiscoKey:          pollRequest.DiscoKey,
			Addresses:         pollRequest.Hostinfo.RoutableIPs, // TODO: need to put wireguard IP here, I guess it's the first item in allowedIps
			AllowedIPs:        pollRequest.Hostinfo.RoutableIPs,
			Endpoints:         pollRequest.Endpoints,
			DERP:              strconv.Itoa(pollRequest.Hostinfo.NetInfo.PreferredDERP),
			Hostinfo:          *pollRequest.Hostinfo,
			Created:           time.Now(),
			LastSeen:          nil,
			KeepAlive:         pollRequest.KeepAlive,
			MachineAuthorized: true,
		}
		resp.Node = &node
		resp.DERPMap = derpmap.Prod()
		host := s.addNewHost(&node, derpmap.Prod(), s.knownHost, tailcfg.MachineKey(clientMachineKey))
		peers := []*tailcfg.Node{}
		for _, nodeId := range host.Peers {
			peers = append(peers, s.hosts[nodeId].Node)
		}
		resp.Peers = peers
	}

	resBody, err := encode(resp, &clientMachineKey, &s.privateKey)
	if err != nil {
		panic("Encode login response failure.")
	}

	w.Write(resBody)
}

func (s *ControlServer) MetaCert() []byte { return s.metaCert }
