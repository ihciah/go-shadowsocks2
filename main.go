package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/juju/gnuflag"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

const (
	schemeSs = "ss"
	schemeH2 = "h2"
)

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
}

var (
	isVpn bool

	aclListPath string

	timeout int

	dialer *net.Dialer

	fakeDns *FakeDns

	ssPlugin *SsPlugin
)

func logf(f string, v ...interface{}) {
	if config.Verbose {
		log.Printf(f, v...)
	}
}

func main() {
	runtime.GOMAXPROCS(1)

	var flags struct {
		Client   string
		Cipher   string
		Password string
		Socks    string
	}

	flag := gnuflag.NewFlagSet(os.Args[0], gnuflag.ContinueOnError)

	var bindAddr string
	var bindPort int
	var confPath string
	flag.BoolVar(&isVpn, "V", false, "vpn mode")
	flag.StringVar(&bindAddr, "b", "", "client bind address")
	flag.IntVar(&bindPort, "l", 0, "client bind port")
	flag.StringVar(&confPath, "c", "", "conf path")
	flag.StringVar(&aclListPath, "acl", "", "acl")
	flag.Bool("fast-open", false, "fast-open")
	flag.IntVar(&timeout, "t", 60, "timeout")

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	flag.Bool("u", false, "(client-only) Enable UDP support for SOCKS")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse(false, os.Args[1:])

	dialer = &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}
	if isVpn {
		pwd, _ := os.Getwd()

		if !config.Verbose {
			if _, err := os.Stat("verbose"); err == nil {
				config.Verbose = true
			}
		}

		f, _ := os.OpenFile("sslocal.stdout", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		log.SetOutput(f)
		redirectStream(f.Fd())
		fmt.Fprintf(os.Stderr, "%v\n", os.Args)
		log.Printf("now in vpn mode, pwd: %s", pwd)
	}

	if bindAddr != "" && bindPort > 0 {
		flags.Socks = fmt.Sprintf("%s:%d", bindAddr, bindPort)
	}
	if confPath != "" {
		type jsonConf struct {
			Server   string `json:"server"`
			Port     int    `json:"server_port"`
			Password string `json:"password"`
			Method   string `json:"method"`

			PluginCmd  string `json:"plugin"`
			PluginOpts string `json:"plugin_opts"`
		}
		b, err := ioutil.ReadFile(confPath)
		if err != nil {
			log.Fatalf("read %s: %v", confPath, err)
		}
		var c jsonConf
		if err := json.Unmarshal(b, &c); err != nil {
			log.Fatalf("parse json conf: %v", err)
		}
		var ssUrl *url.URL
		if strings.ToLower(c.Method) == "xchacha20-ietf-poly1305" {
			parts := strings.SplitN(c.Password, ":", 2)
			u := parts[0]
			p := ""
			if len(parts) > 1 {
				p = parts[1]
			}
			ssUrl = &url.URL{
				Scheme: schemeH2,
				User:   url.UserPassword(u, p),
			}
		} else {
			ssUrl = &url.URL{
				Scheme: schemeSs,
				User:   url.UserPassword(c.Method, c.Password),
			}
		}
		if isVpn {
			fakeDns = NewFakeDns()
			go fakeDns.Start()
			go sendStat()
		}
		if c.PluginCmd != "" {
			ssPlugin = NewSsPlugin(c.PluginCmd, c.PluginOpts, c.Server, c.Port)
			ssUrl.Host = ssPlugin.Host()
			log.Printf("plugin: %s -> %s:%d", ssUrl.Host, c.Server, c.Port)
			log.Printf("plugin: %s, opts: %s", c.PluginCmd, c.PluginOpts)
			go ssPlugin.Start()
		} else {
			ssUrl.Host = fmt.Sprintf("%s:%d", c.Server, c.Port)
		}
		flags.Client = ssUrl.String()
	}

	if flags.Client != "" { // client mode
		scheme := schemeSs
		addr := flags.Client
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.Contains(addr, "://") {
			scheme, addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		var connDial func(string, string) (net.Conn, error)
		switch scheme {
		case schemeSs:
			ciph, err := core.PickCipher(cipher, nil, password)
			if err != nil {
				log.Fatal(err)
			}
			connDial = ssShadow(addr, ciph)
		case schemeH2:
			connDial = h2Shadow(addr, cipher, password)
		default:
			log.Fatalf("unsupported scheme: %s", scheme)
		}

		logf("SOCKS proxy %s <-> %s", flags.Socks, addr)
		go socksLocal(flags.Socks, connDial)
	} else {
		flag.PrintDefaults()
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func parseURL(s string) (scheme, addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	scheme = u.Scheme
	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
