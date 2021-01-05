// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/control/controlclient"
	"tailscale.com/tstest"
	"tailscale.com/wgengine/router"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := 0; i < t.NumField(); i++ {
		fields = append(fields, t.Field(i).Name)
	}
	return
}

func TestPrefsEqual(t *testing.T) {
	tstest.PanicOnLog()

	prefsHandles := []string{"ControlURL", "RouteAll", "AllowSingleHosts", "CorpDNS", "WantRunning", "ShieldsUp", "AdvertiseTags", "Hostname", "OSVersion", "DeviceModel", "NotepadURLs", "ForceDaemon", "AdvertiseRoutes", "NoSNAT", "NetfilterMode", "Persist"}
	if have := fieldsOf(reflect.TypeOf(Prefs{})); !reflect.DeepEqual(have, prefsHandles) {
		t.Errorf("Prefs.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, prefsHandles)
	}

	nets := func(strs ...string) (ns []wgcfg.CIDR) {
		for _, s := range strs {
			n, err := wgcfg.ParseCIDR(s)
			if err != nil {
				panic(err)
			}
			ns = append(ns, n)
		}
		return ns
	}
	tests := []struct {
		a, b *Prefs
		want bool
	}{
		{
			&Prefs{},
			nil,
			false,
		},
		{
			nil,
			&Prefs{},
			false,
		},
		{
			&Prefs{},
			&Prefs{},
			true,
		},

		{
			&Prefs{ControlURL: "https://login.tailscale.com"},
			&Prefs{ControlURL: "https://login.private.co"},
			false,
		},
		{
			&Prefs{ControlURL: "https://login.tailscale.com"},
			&Prefs{ControlURL: "https://login.tailscale.com"},
			true,
		},

		{
			&Prefs{RouteAll: true},
			&Prefs{RouteAll: false},
			false,
		},
		{
			&Prefs{RouteAll: true},
			&Prefs{RouteAll: true},
			true,
		},

		{
			&Prefs{AllowSingleHosts: true},
			&Prefs{AllowSingleHosts: false},
			false,
		},
		{
			&Prefs{AllowSingleHosts: true},
			&Prefs{AllowSingleHosts: true},
			true,
		},

		{
			&Prefs{CorpDNS: true},
			&Prefs{CorpDNS: false},
			false,
		},
		{
			&Prefs{CorpDNS: true},
			&Prefs{CorpDNS: true},
			true,
		},

		{
			&Prefs{WantRunning: true},
			&Prefs{WantRunning: false},
			false,
		},
		{
			&Prefs{WantRunning: true},
			&Prefs{WantRunning: true},
			true,
		},

		{
			&Prefs{NoSNAT: true},
			&Prefs{NoSNAT: false},
			false,
		},
		{
			&Prefs{NoSNAT: true},
			&Prefs{NoSNAT: true},
			true,
		},

		{
			&Prefs{Hostname: "android-host01"},
			&Prefs{Hostname: "android-host02"},
			false,
		},
		{
			&Prefs{Hostname: ""},
			&Prefs{Hostname: ""},
			true,
		},

		{
			&Prefs{NotepadURLs: true},
			&Prefs{NotepadURLs: false},
			false,
		},
		{
			&Prefs{NotepadURLs: true},
			&Prefs{NotepadURLs: true},
			true,
		},

		{
			&Prefs{ShieldsUp: true},
			&Prefs{ShieldsUp: false},
			false,
		},
		{
			&Prefs{ShieldsUp: true},
			&Prefs{ShieldsUp: true},
			true,
		},

		{
			&Prefs{AdvertiseRoutes: nil},
			&Prefs{AdvertiseRoutes: []wgcfg.CIDR{}},
			true,
		},
		{
			&Prefs{AdvertiseRoutes: []wgcfg.CIDR{}},
			&Prefs{AdvertiseRoutes: []wgcfg.CIDR{}},
			true,
		},
		{
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.1.0.0/16")},
			&Prefs{AdvertiseRoutes: nets("192.168.1.0/24", "10.2.0.0/16")},
			false,
		},
		{
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.1.0.0/16")},
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.2.0.0/16")},
			false,
		},
		{
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.1.0.0/16")},
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.1.0.0/16")},
			true,
		},

		{
			&Prefs{NetfilterMode: router.NetfilterOff},
			&Prefs{NetfilterMode: router.NetfilterOn},
			false,
		},
		{
			&Prefs{NetfilterMode: router.NetfilterOn},
			&Prefs{NetfilterMode: router.NetfilterOn},
			true,
		},

		{
			&Prefs{Persist: &controlclient.Persist{}},
			&Prefs{Persist: &controlclient.Persist{LoginName: "dave"}},
			false,
		},
		{
			&Prefs{Persist: &controlclient.Persist{LoginName: "dave"}},
			&Prefs{Persist: &controlclient.Persist{LoginName: "dave"}},
			true,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equals(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}

func checkPrefs(t *testing.T, p Prefs) {
	var err error
	var p2, p2c *Prefs
	var p2b *Prefs

	pp := p.Pretty()
	if pp == "" {
		t.Fatalf("default p.Pretty() failed\n")
	}
	t.Logf("\npp:   %#v\n", pp)
	b := p.ToBytes()
	if len(b) == 0 {
		t.Fatalf("default p.ToBytes() failed\n")
	}
	if !p.Equals(&p) {
		t.Fatalf("p != p\n")
	}
	p2 = p.Clone()
	p2.RouteAll = true
	if p.Equals(p2) {
		t.Fatalf("p == p2\n")
	}
	p2b, err = PrefsFromBytes(p2.ToBytes(), false)
	if err != nil {
		t.Fatalf("PrefsFromBytes(p2) failed\n")
	}
	p2p := p2.Pretty()
	p2bp := p2b.Pretty()
	t.Logf("\np2p:  %#v\np2bp: %#v\n", p2p, p2bp)
	if p2p != p2bp {
		t.Fatalf("p2p != p2bp\n%#v\n%#v\n", p2p, p2bp)
	}
	if !p2.Equals(p2b) {
		t.Fatalf("p2 != p2b\n%#v\n%#v\n", p2, p2b)
	}
	p2c = p2.Clone()
	if !p2b.Equals(p2c) {
		t.Fatalf("p2b != p2c\n")
	}
}

func TestBasicPrefs(t *testing.T) {
	tstest.PanicOnLog()

	p := Prefs{
		ControlURL: "https://login.tailscale.com",
	}
	checkPrefs(t, p)
}

func TestPrefsPersist(t *testing.T) {
	tstest.PanicOnLog()

	c := controlclient.Persist{
		LoginName: "test@example.com",
	}
	p := Prefs{
		ControlURL: "https://login.tailscale.com",
		CorpDNS:    true,
		Persist:    &c,
	}
	checkPrefs(t, p)
}

func TestPrefsPretty(t *testing.T) {
	tests := []struct {
		p    Prefs
		os   string
		want string
	}{
		{
			Prefs{},
			"linux",
			"Prefs{ra=false mesh=false dns=false want=false routes=[] nf=off Persist=nil}",
		},
		{
			Prefs{},
			"windows",
			"Prefs{ra=false mesh=false dns=false want=false Persist=nil}",
		},
		{
			Prefs{ShieldsUp: true},
			"windows",
			"Prefs{ra=false mesh=false dns=false want=false shields=true Persist=nil}",
		},
		{
			Prefs{AllowSingleHosts: true},
			"windows",
			"Prefs{ra=false dns=false want=false Persist=nil}",
		},
		{
			Prefs{
				NotepadURLs:      true,
				AllowSingleHosts: true,
			},
			"windows",
			"Prefs{ra=false dns=false want=false notepad=true Persist=nil}",
		},
		{
			Prefs{
				AllowSingleHosts: true,
				WantRunning:      true,
				ForceDaemon:      true, // server mode
			},
			"windows",
			"Prefs{ra=false dns=false want=true server=true Persist=nil}",
		},
		{
			Prefs{
				AllowSingleHosts: true,
				WantRunning:      true,
				ControlURL:       "http://localhost:1234",
				AdvertiseTags:    []string{"tag:foo", "tag:bar"},
			},
			"darwin",
			`Prefs{ra=false dns=false want=true tags=tag:foo,tag:bar url="http://localhost:1234" Persist=nil}`,
		},
		{
			Prefs{
				Persist: &controlclient.Persist{},
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false routes=[] nf=off Persist{lm=, o=, n= u=""}}`,
		},
		{
			Prefs{
				Persist: &controlclient.Persist{
					PrivateNodeKey: wgcfg.PrivateKey{1: 1},
				},
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false routes=[] nf=off Persist{lm=, o=, n=[B1VKl] u=""}}`,
		},
	}
	for i, tt := range tests {
		got := tt.p.pretty(tt.os)
		if got != tt.want {
			t.Errorf("%d. wrong String:\n got: %s\nwant: %s\n", i, got, tt.want)
		}
	}
}

func TestLoadPrefsNotExist(t *testing.T) {
	bogusFile := fmt.Sprintf("/tmp/not-exist-%d", time.Now().UnixNano())

	p, err := LoadPrefs(bogusFile)
	if errors.Is(err, os.ErrNotExist) {
		// expected.
		return
	}
	t.Fatalf("unexpected prefs=%#v, err=%v", p, err)
}

// TestLoadPrefsFileWithZeroInIt verifies that LoadPrefs hanldes corrupted input files.
// See issue #954 for details.
func TestLoadPrefsFileWithZeroInIt(t *testing.T) {
	f, err := ioutil.TempFile("", "TestLoadPrefsFileWithZeroInIt")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	if _, err := f.Write(jsonEscapedZero); err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(path)

	p, err := LoadPrefs(path)
	if errors.Is(err, os.ErrNotExist) {
		// expected.
		return
	}
	t.Fatalf("unexpected prefs=%#v, err=%v", p, err)
}
