package controller

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/crypto/acme/autocert"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"tailscale.com/atomicfile"
	"tailscale.com/control/controlserver"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
)

var (
	dev           = flag.Bool("dev", false, "run in localhost development mode")
	addr          = flag.String("a", ":443", "server address")
	configPath    = flag.String("c", "", "config file path")
	hostname      = flag.String("hostname", "controlserver.octet.com", "LetsEncrypt host name, if addr's port is :443")
	certDir       = flag.String("certdir", tsweb.DefaultCertDir("derper-certs"), "directory to store LetsEncrypt certs, if addr's port is :443")
)

type config struct {
	PrivateKey wgcfg.PrivateKey
}

func loadConfig() config {
	if *dev {
		return config{PrivateKey: mustNewKey()}
	}
	if *configPath == "" {
		log.Fatalf("derper: -c <config path> not specified")
	}
	b, err := ioutil.ReadFile(*configPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return writeNewConfig()
	case err != nil:
		log.Fatal(err)
		panic("unreachable")
	default:
		var cfg config
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Fatalf("derper: config: %v", err)
		}
		return cfg
	}
}

func mustNewKey() wgcfg.PrivateKey {
	key, err := wgcfg.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func writeNewConfig() config {
	key := mustNewKey()
	if err := os.MkdirAll(filepath.Dir(*configPath), 0777); err != nil {
		log.Fatal(err)
	}
	cfg := config{
		PrivateKey: key,
	}
	b, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	if err := atomicfile.WriteFile(*configPath, b, 0666); err != nil {
		log.Fatal(err)
	}
	return cfg
}

func debugHandler(s *controlserver.ControlServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }
		f(`<html><body>
<h1>ControlServer debug</h1>
<ul>
`)
		f("<li><b>Uptime:</b> %v</li>\n", tsweb.Uptime())

		f(`<li><a href="/debug/vars">/debug/vars</a> (Go)</li>
   <li><a href="/debug/varz">/debug/varz</a> (Prometheus)</li>
   <li><a href="/debug/pprof/">/debug/pprof/</a></li>
   <li><a href="/debug/pprof/goroutine?debug=1">/debug/pprof/goroutine</a> (collapsed)</li>
   <li><a href="/debug/pprof/goroutine?debug=2">/debug/pprof/goroutine</a> (full)</li>
<ul>
</html>
`)
	})
}

var validProdHostname = regexp.MustCompile(`^controlserver([^.]*)\.octet\.com\.?$`)

func prodAutocertHostPolicy(_ context.Context, host string) error {
	if validProdHostname.MatchString(host) {
		return nil
	}
	return errors.New("invalid hostname")
}

func main() {
	flag.Parse()

	if *dev {
		*addr = ":443"
		log.Printf("Running in dev mode.")
		tsweb.DevMode = true
	}

	cfg := loadConfig()
	letsEncrypt := tsweb.IsProd443(*addr)
	s := controlserver.NewServer(key.Private(cfg.PrivateKey), log.Printf)

	mux := tsweb.NewMux(debugHandler(s))

	mux.Handle("/", controlserver.Router(s))

	httpsrv := &http.Server{
		Addr: *addr,
		Handler: mux,
	}

	var err error
	if letsEncrypt {
		if *certDir == "" {
			log.Fatalf("missing required --certdir flag")
		}
		log.Printf("controlserver: serving on %s with TLS", *addr)
		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*hostname),
			Cache:      autocert.DirCache(*certDir),
		}
		if *hostname == "controlserver.octet.com" {
			certManager.HostPolicy = prodAutocertHostPolicy
			certManager.Email = "security@octet.com"
		}
		httpsrv.TLSConfig = certManager.TLSConfig()
		letsEncryptGetCert := httpsrv.TLSConfig.GetCertificate
		httpsrv.TLSConfig.GetCertificate = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := letsEncryptGetCert(hi)
			if err != nil {
				return nil, err
			}
			cert.Certificate = append(cert.Certificate, s.MetaCert())
			return cert, nil
		}
		go func() {
			err := http.ListenAndServe(":80", certManager.HTTPHandler(tsweb.Port80Handler{Main: mux}))
			if err != nil {
				if err != http.ErrServerClosed {
					log.Fatal(err)
				}
			}
		}()
		err = httpsrv.ListenAndServeTLS("", "")
	} else {
		log.Printf("controlserver: serving on %s", *addr)
		err = httpsrv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("controlserver: %v", err)
	}
}