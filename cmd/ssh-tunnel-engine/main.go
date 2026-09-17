package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

func main() {
	device := flag.String("device", "", "TUN device URI")
	proxy := flag.String("proxy", "", "SOCKS5 proxy URI")
	flag.Parse()
	if *device == "" || *proxy == "" {
		os.Exit(2)
	}

	engine.Insert(&engine.Key{Device: *device, Proxy: *proxy, MTU: 1500})
	engine.Start()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	engine.Stop()
}
