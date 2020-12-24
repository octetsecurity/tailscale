// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package systemd

import (
	"log"
	"os"
	"sync"

	"github.com/mdlayher/sdnotify"
)

var getNotifyOnce struct {
	sync.Once
	v *sdnotify.Notifier
}

type logOnce struct {
	sync.Once
}

func (l *logOnce) logf(format string, args ...interface{}) {
	l.Once.Do(func() {
		log.Printf(format, args...)
	})
}

var (
	readyOnce  = &logOnce{}
	statusOnce = &logOnce{}
)

func notifier() *sdnotify.Notifier {
	getNotifyOnce.Do(func() {
		sock := os.Getenv(sdnotify.Socket)
		if sock == "" {
			// Not running under systemd probably. Bail out before logging.
			return
		}
		var err error
		getNotifyOnce.v, err = sdnotify.Open(sock)
		if err != nil {
			log.Printf("systemd: systemd-notifier error: %v", err)
		}
	})
	return getNotifyOnce.v
}

// Ready signals readiness to systemd. This will unblock service dependents from starting.
func Ready() {
	err := notifier().Notify(sdnotify.Ready)
	if err != nil {
		readyOnce.logf("systemd: error notifying: %v", err)
	}
}

// Status sends a single line status update to systemd so that information shows up
// in systemctl output. For example:
//
//    $ systemctl status tailscale
//    ● tailscale.service - Tailscale client daemon
//    Loaded: loaded (/nix/store/qc312qcy907wz80fqrgbbm8a9djafmlg-unit-tailscale.service/tailscale.service; enabled; vendor preset: enabled)
//    Active: active (running) since Tue 2020-11-24 17:54:07 EST; 13h ago
//    Main PID: 26741 (.tailscaled-wra)
//    Status: "Connected; user@host.domain.tld; 100.101.102.103"
//    IP: 0B in, 0B out
//    Tasks: 22 (limit: 4915)
//    Memory: 30.9M
//    CPU: 2min 38.469s
//    CGroup: /system.slice/tailscale.service
//    └─26741 /nix/store/sv6cj4mw2jajm9xkbwj07k29dj30lh0n-tailscale-date.20200727/bin/tailscaled --port 41641
func Status(format string, args ...interface{}) {
	err := notifier().Notify(sdnotify.Statusf(format, args...))
	if err != nil {
		statusOnce.logf("systemd: error notifying: %v", err)
	}
}
