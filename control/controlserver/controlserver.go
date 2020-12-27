package controlserver

import (
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
	Node *tailcfg.Node
	DERPMap *tailcfg.DERPMap
	Peers []*tailcfg.NodeID
	PeersChanged []*tailcfg.NodeID
	PeersRemoved []tailcfg.NodeID
}

type ControlServer struct {
	privateKey key.Private
	publicKey key.Public
	logf logger.Logf
	metaCert    []byte // the encoded x509 cert to send after LetsEncrypt cert+intermediate
	groups map[tailcfg.GroupID]*tailcfg.Group
	users map[tailcfg.UserID]*tailcfg.User
	hosts map[tailcfg.NodeID]*Host
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

func encode(v interface{}, clientKey *wgcfg.Key, mkey *wgcfg.PrivateKey) ([]byte, error) {
	return nil, nil
}

func decode(res *http.Response, v interface{}, clientKey *wgcfg.Key, mkey *wgcfg.PrivateKey) error {
	return nil
}

func Router(s *ControlServer) http.Handler{
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

func loginHandler(s *ControlServer, w http.ResponseWriter, r *http.Request) http.Handler{
	return nil
}

func pollNetMapHandler(s *ControlServer, w http.ResponseWriter, r *http.Request) http.Handler{
	return nil
}

func (s *ControlServer) MetaCert() []byte { return s.metaCert }