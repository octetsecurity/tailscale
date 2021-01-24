package controlserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/crypto/nacl/box"
	"inet.af/netaddr"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	rand2 "math/rand"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"tailscale.com/derp/derpmap"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/wgkey"
	"time"
)

type Host struct {
	Node         *tailcfg.Node
	DERPMap      *tailcfg.DERPMap
	Peers        []tailcfg.NodeID
	PeersChanged []tailcfg.NodeID
	PeersRemoved []tailcfg.NodeID
}

type Compressor interface {
	EncodeAll(src, dst []byte) []byte
	Close() error
}

type ControlServer struct {
	privateKey       key.Private
	publicKey        key.Public
	serverPrivateKey wgkey.Private
	logf             logger.Logf
	newCompressor    func() (Compressor, error)
	metaCert         []byte // the encoded x509 cert to send after LetsEncrypt cert+intermediate
	groups           map[tailcfg.GroupID]*tailcfg.Group
	users            map[tailcfg.UserID]*tailcfg.User
	hosts            map[tailcfg.NodeID]*Host
	knownHost        map[tailcfg.MachineKey]tailcfg.NodeID
	tailscaleIps	 map[tailcfg.NodeID]netaddr.IPPrefix
}

func (s *ControlServer) initMetacert() {
	pub, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("derpkey%x", s.publicKey[:]),
		},
		// Windows requires NotAfter and NotBefore set:
		NotAfter:  time.Now().Add(30 * 24 * time.Hour),
		NotBefore: time.Now().Add(-30 * 24 * time.Hour),
	}
	cert, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		log.Fatalf("CreateCertificate: %v", err)
	}
	s.metaCert = cert
}

func NewServer(privateKey key.Private, logf logger.Logf) *ControlServer {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	serverKey, err := wgkey.NewPrivate()
	if err != nil {
		fmt.Println("fail to create controlserver")
		return nil
	}

	s := &ControlServer{
		privateKey:       privateKey,
		publicKey:        privateKey.Public(),
		serverPrivateKey: serverKey,
		logf:             logf,
		groups:           map[tailcfg.GroupID]*tailcfg.Group{},
		users:            map[tailcfg.UserID]*tailcfg.User{},
		hosts:            map[tailcfg.NodeID]*Host{},
		knownHost:        map[tailcfg.MachineKey]tailcfg.NodeID{},
		tailscaleIps:	  map[tailcfg.NodeID]netaddr.IPPrefix{},
	}
	s.SetNewCompressor(func() (Compressor, error) {
		return smallzstd.NewEncoder(nil)
	})

	s.initMetacert()

	return s
}

func (s *ControlServer) SetNewCompressor(fn func() (Compressor, error)) {
	s.newCompressor = fn
}

func encode(v interface{}, clientKey *wgcfg.Key, mkey *wgkey.Private) ([]byte, error) {
	// Server encoding a response it sends to a client
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	pub, pri := (*[32]byte)(clientKey), (*[32]byte)(mkey)
	msg := box.Seal(nonce[:], b, &nonce, pub, pri)
	return msg, nil
}

func (s *ControlServer) encodeAndCompress(v interface{}, clientKey *wgcfg.Key, mkey *wgkey.Private) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	encoder, err := s.newCompressor()
	if err != nil {
		return nil, err
	}
	defer encoder.Close()
	out := []byte{}
	out = encoder.EncodeAll(b, out)

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	pub, pri := (*[32]byte)(clientKey), (*[32]byte)(mkey)
	msg := box.Seal(nonce[:], out, &nonce, pub, pri)
	return msg, nil
}

func decode(req *http.Request, v interface{}, clientKey *wgcfg.Key, mkey *wgkey.Private) error {
	// Server decoding a request it receives from a client
	// req is the http.Request received by the server
	defer req.Body.Close()
	msg, err := ioutil.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		return err
	}
	// Call decodeMsg to set v
	return decodeMsg(msg, v, clientKey, mkey)
}

var jsonEscapedZero = []byte(`\u0000`)

func decodeMsg(msg []byte, v interface{}, clientKey *wgcfg.Key, mkey *wgkey.Private) error {
	// Call decryptMsg to obtain decrypted, which will be used to unmarshal into v
	decrypted, err := decryptMsg(msg, clientKey, mkey)
	if err != nil {
		return err
	}
	if bytes.Contains(decrypted, jsonEscapedZero) {
		log.Printf("[unexpected] zero byte in controlclient decodeMsg into %T: %q", v, decrypted)
	}
	// Unmarshal decrypted into v, thereby achieving our goal
	if err := json.Unmarshal(decrypted, v); err != nil {
		return fmt.Errorf("response: %v", err)
	}
	return nil
}

func decryptMsg(msg []byte, clientKey *wgcfg.Key, mkey *wgkey.Private) ([]byte, error) {
	var nonce [24]byte
	if len(msg) < len(nonce)+1 {
		return nil, fmt.Errorf("request missing nonce, len=%d", len(msg))
	}
	copy(nonce[:], msg)
	msg = msg[len(nonce):]

	pub, pri := (*[32]byte)(clientKey), (*[32]byte)(mkey)
	decrypted, ok := box.Open(nil, msg, &nonce, pub, pri)
	if !ok {
		return nil, fmt.Errorf("cannot decrypt request (len %d + nonce %d = %d)", len(msg), len(nonce), len(msg)+len(nonce))
	}
	return decrypted, nil
}

func (s *ControlServer) ServerKeyPublisher(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		io.WriteString(w, "Method not allowed")
		return
	}
	fmt.Println("ServerKey is ", s.serverPrivateKey.Public().String())
	fmt.Fprintf(w, s.serverPrivateKey.Public().HexString())
}

func (s *ControlServer) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		io.WriteString(w, "Method not allowed")
		return
	}
	vars := mux.Vars(r)
	clientMachineKey, err := wgcfg.ParseHexKey(vars["clientMachineKey"])
	fmt.Println("Client machine key is ", clientMachineKey.String())
	if err != nil {
		io.WriteString(w, "client machine key invalid")
		return
	}

	request := tailcfg.RegisterRequest{}
	if err := decode(r, &request, &clientMachineKey, &s.serverPrivateKey); err != nil {
		panic("Decode login request failure")
	}

	// TODO: implement login logic

	login := tailcfg.Login{
		ID:            1,
		Provider:      "provider",
		LoginName:     "OctetTest",
		DisplayName:   "OctetTest",
		ProfilePicURL: "",
		Domain:        "Octet",
	}

	res := tailcfg.RegisterResponse{
		User:              tailcfg.User{},
		Login:             login,
		NodeKeyExpired:    false,
		MachineAuthorized: false,
		AuthURL:           "",
	}

	resBody, err := encode(res, &clientMachineKey, &s.serverPrivateKey)
	if err != nil {
		panic("Encode login response failure.")
	}

	w.Write(resBody)
}

func idGenerator() int64 {
	u := uuid.New().ID()
	return int64(u)
}

func (s *ControlServer) broadcastNewHost(newHostNodeId tailcfg.NodeID) {
	for _, nodeId := range s.knownHost {
		if nodeId != newHostNodeId {
			s.hosts[nodeId].Peers = append(s.hosts[nodeId].Peers, newHostNodeId)
		}

	}
}

func (s *ControlServer) addNewHost(node *tailcfg.Node, derpMap *tailcfg.DERPMap,
	machineKey tailcfg.MachineKey, tailscaleIp netaddr.IPPrefix) Host {
	knownHostCopy := s.knownHost
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
	s.tailscaleIps[node.ID] = tailscaleIp
	s.broadcastNewHost(node.ID)

	return host
}

func (s *ControlServer) broadcastHostChanged(changedNodeId tailcfg.NodeID) {
	for _, nodeId := range s.knownHost {
		for _, peerNodeId := range s.hosts[nodeId].Peers {
			if peerNodeId == changedNodeId {
				s.hosts[nodeId].PeersChanged = append(s.hosts[nodeId].PeersChanged, changedNodeId)
			}
		}
	}
}

//func waitForChange(ctx context.Context, notifyChan chan int) tailcfg.MapResponse {
//	waiter := time.Tick(10 * time.Second)
//	log.Printf("will wait up to 10s for the resource")
//
//	select {
//	case <-ctx.Done():
//		log.Printf("Received context cancel")
//		return tailcfg.MapResponse{}
//	case ts := <-waiter:
//		log.Printf("Received method timeout: %s", ts)
//		return tailcfg.MapResponse{}
//	case _ = <-notifyChan:
//		log.Printf("Received resource update")
//		return
//	}
//}

//func resourceUpdateHandler() tailcfg.MapResponse {
//	resp := tailcfg.MapResponse{
//		KeepAlive:    false,
//		Node:         nil,
//		DERPMap:      nil,
//		Peers:        nil,
//		PeersChanged: nil,
//		PeersRemoved: nil,
//		DNS:          nil,
//		SearchPaths:  nil,
//		DNSConfig:    tailcfg.DNSConfig{},
//		Domain:       "",
//		PacketFilter: nil,
//		UserProfiles: nil,
//		Roles:        nil,
//		Debug:        nil,
//	}
//
//}

func (s *ControlServer) generateTailScaleIp() netaddr.IPPrefix {
	// TODO implement ip generation logic
	randomIp := "100." + strconv.Itoa(rand2.Intn(50)+64) + "." + strconv.Itoa(rand2.Intn(127)) + "." + strconv.Itoa(rand2.Intn(127)) + "/32"
	ip, err := netaddr.ParseIPPrefix(randomIp)
	if err != nil {
		return netaddr.IPPrefix{}
	}
	return ip
}

func (s *ControlServer) PollNetMapHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		io.WriteString(w, "Method not allowed")
		return
	}
	vars := mux.Vars(r)
	clientMachineKey, err := wgcfg.ParseHexKey(vars["clientMachineKey"])
	if err != nil {
		io.WriteString(w, "client machine key invalid")
		return
	}

	pollRequest := tailcfg.MapRequest{}
	if err := decode(r, &pollRequest, &clientMachineKey, &s.serverPrivateKey); err != nil {
		panic("Decode pollNetMap request failure")
	}

	filterRule := tailcfg.FilterRule{
		SrcIPs:   []string{"*"},
		SrcBits:  nil,
		DstPorts: []tailcfg.NetPortRange{tailcfg.NetPortRange{
				IP:    "*",
				Ports: tailcfg.PortRange{
					First: 0,
					Last:  65535,
				},
			},
		},
	}

	resp := tailcfg.MapResponse{
		// TODO: implement keepAlive logic when response is too long
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
		PacketFilter: []tailcfg.FilterRule{filterRule},
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

		if pollRequest.Hostinfo != nil && !pollRequest.Hostinfo.Equal(&host.Node.Hostinfo) {
			// update node info
			fmt.Println("New hostInfo is ", pollRequest.Hostinfo)
			if pollRequest.Hostinfo.NetInfo != nil {
				host.Node.DERP = derpmap.Prod().Regions[pollRequest.Hostinfo.NetInfo.PreferredDERP].Nodes[0].IPv4
			}
			host.Node.Hostinfo = *pollRequest.Hostinfo
			hostChanged = true
		}

		if hostChanged {
			// notify other hosts that their peer has changed
			s.broadcastHostChanged(nodeId)
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
		tailscaleIp := s.generateTailScaleIp()
		node := tailcfg.Node{
			ID:                nodeId,
			Name:              "",
			User:              0,
			Key:               pollRequest.NodeKey,
			KeyExpiry:         time.Now().Add(time.Hour * 8760),
			Machine:           tailcfg.MachineKey(clientMachineKey),
			DiscoKey:          pollRequest.DiscoKey,
			Addresses:         []netaddr.IPPrefix{tailscaleIp}, // tailscale Ip generated by server
			AllowedIPs:        []netaddr.IPPrefix{tailscaleIp}, // wireguard allowedIps assigned by server
			Endpoints:         pollRequest.Endpoints,
			DERP:              "",
			Hostinfo:          *pollRequest.Hostinfo,
			Created:           time.Now(),
			LastSeen:          nil,
			KeepAlive:         false,
			MachineAuthorized: true,
		}
		if pollRequest.Hostinfo.NetInfo != nil && pollRequest.Hostinfo.NetInfo.PreferredDERP != 0 {
			node.DERP = strconv.Itoa(pollRequest.Hostinfo.NetInfo.PreferredDERP)
		}
		resp.Node = &node
		resp.DERPMap = derpmap.Prod()
		host := s.addNewHost(&node, derpmap.Prod(), tailcfg.MachineKey(clientMachineKey), tailscaleIp)
		peers := []*tailcfg.Node{}
		for _, nodeId := range host.Peers {
			peers = append(peers, s.hosts[nodeId].Node)
		}
		resp.Peers = peers
	}

	resBody := []byte{}
	if pollRequest.Compress == "zstd" {
		resBody, err = s.encodeAndCompress(resp, &clientMachineKey, &s.serverPrivateKey)
	} else {
		resBody, err = encode(resp, &clientMachineKey, &s.serverPrivateKey)
	}

	if err != nil {
		panic("Encode login response failure.")
	}

	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(resBody)))
	w.Write(size[:])
	w.Write(resBody)
}

func (s *ControlServer) MetaCert() []byte { return s.metaCert }
