package controlserver

import (
	"errors"
	"github.com/tailscale/wireguard-go/wgcfg"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type Host struct {
	Node         *tailcfg.Node
	DERPMap      *tailcfg.DERPMap
	Peers        []*tailcfg.NodeID
	PeersChanged []*tailcfg.NodeID
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
			loginHandler(s, w, r)
		case matchPollMapRequest.MatchString(r.URL.Path):
			pollNetMapHandler(s, w, r)
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

func matchClientKey(reg *regexp.Regexp, url string) (wgcfg.Key, error) {
	var err error
	match := reg.FindStringSubmatch(url)
	if len(match) <= 1 {
		err = errors.New("No clientKey found.")
	}
	clientKey, err := wgcfg.ParseHexKey(match[1])
	return clientKey, err
}

func loginHandler(s *ControlServer, w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		io.WriteString(w, "Method not allowed")
		return
	}
	reg := regexp.MustCompile(`machine/(.*)`)
	clientKey, err := matchClientKey(reg, r.URL.Path)
	if err != nil {
		panic("Parse ClientKey Failure.")
	}
	request := tailcfg.RegisterRequest{}
	if err := decode(r, &request, &clientKey, &s.privateKey); err != nil {
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

	resBody, err := encode(res, &clientKey, &s.privateKey)
	if err != nil {
		panic("Encode login response failure.")
	}

	w.Write(resBody)
}

func pollNetMapHandler(s *ControlServer, w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		io.WriteString(w, "Method not allowed")
		return
	}
	reg := regexp.MustCompile(`machine/(.*)/map`)
	clientKey, err := matchClientKey(reg, r.URL.Path)
	if err != nil {
		panic("Parse ClientKey Failure.")
	}

	pollRequest := tailcfg.MapRequest{}
	if err := decode(r, &pollRequest, &clientKey, &s.privateKey); err != nil {
		panic("Decode pollNetMap request failure")
	}

	// TODO: implement real logic

	res := tailcfg.MapResponse{
		KeepAlive:    false,
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

	resBody, err := encode(res, &clientKey, &s.privateKey)
	if err != nil {
		panic("Encode login response failure.")
	}

	w.Write(resBody)
}

func (s *ControlServer) MetaCert() []byte { return s.metaCert }
