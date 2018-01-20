package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/smallnest/iprange"
)

const (
	dnsTimeout = 6 * time.Second

	alwaysDirectListFile = "fakedns.cache.ad"
)

var (
	directLookupId uint32
)

type DnsError struct {
	rcode int
}

func (e *DnsError) Error() string {
	return fmt.Sprintf("dns error with rcode=%s", dns.RcodeToString[e.rcode])
}

type alwaysDirectRecord struct {
	*sync.RWMutex `json:"-"`
	IPs           []net.IP `json:"ips"`
}

type FakeDns struct {
	bindAddr string

	chinaDNS []string

	probeDNS      []string
	probeDNSMutex *sync.RWMutex

	mapping      map[string]string
	mappingMutex *sync.RWMutex

	alwaysDirectList           map[string]*alwaysDirectRecord
	alwaysDirectListWriteMutex *sync.Mutex

	fakeDnsIp4 uint32

	cacheFile *os.File

	aclRanges []*iprange.IPV4Range
}

func NewFakeDns() *FakeDns {
	var chnDns []string
	var overtureVpnConfPath = []string{"overture-vpn.conf", "overture.conf"}
	var overtureConf = struct {
		BindAddress    string
		AlternativeDNS []struct {
			Address string
		}
	}{}
	for _, path := range overtureVpnConfPath {
		if b, err := ioutil.ReadFile(path); err == nil {
			if err := json.Unmarshal(b, &overtureConf); err == nil {
				for _, d := range overtureConf.AlternativeDNS {
					chnDns = append(chnDns, d.Address)
				}
			} else {
				logf("parse %s: %v", overtureVpnConfPath, err)
			}
		} else {
			logf("read %s: %v", overtureVpnConfPath, err)
		}
	}
	if len(chnDns) == 0 {
		log.Fatalln("can not get custom dns from overture conf file")
	} else {
		logf("chinadns: %v", chnDns)
	}
	return &FakeDns{
		bindAddr: overtureConf.BindAddress,
		chinaDNS: chnDns,

		mapping:      make(map[string]string),
		mappingMutex: &sync.RWMutex{},

		alwaysDirectList:           make(map[string]*alwaysDirectRecord),
		alwaysDirectListWriteMutex: &sync.Mutex{},

		probeDNSMutex: &sync.RWMutex{},
		fakeDnsIp4:    184549376, // 11.0.0.0
	}
}

func (f *FakeDns) Start() {
	cacheWg := &sync.WaitGroup{}
	cacheWg.Add(3)
	go func() {
		defer cacheWg.Done()
		readHosts()
	}()
	go func() {
		const cachePath = "fakedns.cache"
		defer cacheWg.Done()
		var err error
		f.cacheFile, err = os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			log.Fatalf("open %s: %v", cachePath, err)
		}
		scanner := bufio.NewScanner(f.cacheFile)
		cnt := 0
		for scanner.Scan() {
			const (
				directDnsQuery      = "0"
				fakeDnsQuery        = "1"
				alwaysDirectConnect = "2"
			)
			var (
				fakeState string
				domain    string
			)
			line := scanner.Text()
			splitted := strings.Split(line, " ")
			switch len(splitted) {
			case 1:
				domain, fakeState = line, fakeDnsQuery
			case 2:
				domain, fakeState = splitted[0], splitted[1]
			default:
			}
			if domain == "" {
				continue
			}
			switch fakeState {
			case directDnsQuery:
				f.mapping[domain] = ""
			case fakeDnsQuery:
				ip := f.newFakeIp()
				f.mapping[ip] = domain
				f.mapping[domain] = ip
			case alwaysDirectConnect:
				f.mapping[domain] = ""
				f.alwaysDirectList[domain] = &alwaysDirectRecord{
					&sync.RWMutex{},
					nil,
				}
			}
			cnt++
		}
		logf("loaded %s %d items, err: %v", cachePath, cnt, scanner.Err())
		if b, err := ioutil.ReadFile(alwaysDirectListFile); err == nil {
			l := make(map[string]*alwaysDirectRecord)
			if err := json.Unmarshal(b, &l); err == nil {
				cnt = 0
				for k, v := range l {
					if r, ok := f.alwaysDirectList[k]; ok {
						r.IPs = v.IPs
						cnt++
					}
				}
				logf("loaded %s %d items", alwaysDirectListFile, cnt)
			} else {
				logf("decode %s error: %v", alwaysDirectListFile, err)
			}
		} else {
			logf("read %s error: %v", alwaysDirectListFile, err)
		}
	}()
	go func() {
		defer cacheWg.Done()
		if aclListPath == "" {
			return
		}
		f.aclRanges = f.parseAcl(aclListPath)
		lessFunc := func(i, j int) bool {
			return f.aclRanges[i].Start < f.aclRanges[j].Start
		}
		if !sort.SliceIsSorted(f.aclRanges, lessFunc) {
			sort.Slice(f.aclRanges, lessFunc)
		}
		logf("loaded %s %d items", aclListPath, len(f.aclRanges))
	}()

	if err := f.refreshProbeDnsSrv(); err != nil {
		log.Fatalf("refreshProbeDnsSrv: %v", err)
	}
	cacheWg.Wait()
	srv := dns.Server{
		Addr: fmt.Sprintf(f.bindAddr),
		Net:  "udp4",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ok := false
			var q dns.Question
			for i := range r.Question {
				if r.Question[i].Qtype != dns.TypeAAAA {
					q = r.Question[i]
					ok = true
				}
			}
			logf("dns query: %s", q.String())
			if !ok {
				dns.HandleFailed(w, r)
				return
			}
			qName := q.Name
			if q.Qtype == dns.TypeA {
				if staticIps := lookupStaticHost(qName); len(staticIps) > 0 {
					logf("domain %s found in hosts: %v", qName, staticIps)
					respMsg := fakeRespDnsMsg(r, staticIps)
					f.processAlwaysDirect(qName, respMsg)
					w.WriteMsg(respMsg)
					return
				}
			}
			shouldProbe := q.Qtype == dns.TypeA && strings.Count(qName, ".") > 1
			r.Question = []dns.Question{q}
			respMsg := func() *dns.Msg {
				var fakeIp string
				f.mappingMutex.RLock()
				fakeIp, ok := f.mapping[qName]
				f.mappingMutex.RUnlock()
				if ok {
					if fakeIp != "" {
						return fakeRespDnsMsg(r, []string{fakeIp})
					} else {
						shouldProbe = false
					}
				}
				probeCh := make(chan string, 1)
				if shouldProbe {
					go func() {
						defer close(probeCh)
						f.probeDNSMutex.RLock()
						probeDNS := f.probeDNS
						f.probeDNSMutex.RUnlock()
						resp, err := directQueryWithMsg(r, probeDNS)
						if err != nil {
							return
						}
						if resp.Rcode == dns.RcodeSuccess {
							logf("domain %s polluted", qName)
							ip := f.newFakeIp()
							f.insertFakeDnsRecord(ip, qName)
							probeCh <- ip
						}
					}()
				}
				realCh := make(chan *dns.Msg, 1)
				go func() {
					defer close(realCh)
					resp, err := directQueryWithMsg(r, f.chinaDNS)
					if err == nil {
						realCh <- resp
					} else {
						realCh <- nil
					}
				}()
				var respMsg *dns.Msg
				select {
				case fakeIp = <-probeCh:
					if fakeIp != "" {
						return fakeRespDnsMsg(r, []string{fakeIp})
					} else {
						respMsg = <-realCh
					}
				case respMsg = <-realCh:
					if shouldProbe {
						fakeIp = <-probeCh
						if fakeIp != "" {
							return fakeRespDnsMsg(r, []string{fakeIp})
						}
					}
				}
				if respMsg == nil {
					respMsg = failedDnsMsg(r)
				} else {
					if respMsg.Rcode == dns.RcodeServerFailure {
						fakeIp := f.newFakeIp()
						f.insertFakeDnsRecord(fakeIp, qName)
						return fakeRespDnsMsg(r, []string{fakeIp})
					}
				}
				if respMsg.Rcode == dns.RcodeSuccess {
					f.processAlwaysDirect(qName, respMsg)
					var chnAnswers []dns.RR
					var chnACnt int
					for _, answer := range respMsg.Answer {
						if dnsA, ok := answer.(*dns.A); ok {
							if f.ShouldDirectConnect(dnsA.A) {
								dnsA.Hdr.Ttl = 3600
								chnAnswers = append(chnAnswers, dnsA)
								chnACnt++
							}
						} else {
							chnAnswers = append(chnAnswers, answer)
						}
					}
					if chnACnt == 0 {
						if shouldProbe {
							logf("domain %s has no chn ips, fake it", qName)
							fakeIp = f.newFakeIp()
							f.insertFakeDnsRecord(fakeIp, qName)
							respMsg = fakeRespDnsMsg(r, []string{fakeIp})
						}
					} else {
						respMsg.Answer = chnAnswers
					}
				}
				return respMsg
			}()
			if shouldProbe {
				f.mappingMutex.Lock()
				_, ok = f.mapping[qName]
				if !ok {
					f.insertFakeDnsRecordWithoutLock("", qName)
				}
				f.mappingMutex.Unlock()
			}
			w.WriteMsg(respMsg)
		}),
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("dns listen: %v", err)
	}
}

func (f *FakeDns) processAlwaysDirect(qName string, respMsg *dns.Msg) {
	if adr := f.alwaysDirectList[qName]; adr != nil {
		ips := make([]net.IP, 0, len(respMsg.Answer))
		for _, answer := range respMsg.Answer {
			if dnsA, ok := answer.(*dns.A); ok {
				ips = append(ips, dnsA.A)
			}
		}
		adr.Lock()
		oldIps := adr.IPs
		adr.IPs = ips
		adr.Unlock()
		if !netIPSlicesEquals(oldIps, ips) {
			go func() {
				f.alwaysDirectListWriteMutex.Lock()
				defer f.alwaysDirectListWriteMutex.Unlock()
				b, err := json.Marshal(f.alwaysDirectList)
				if err != nil {
					logf("marshal alwaysDirectList error: %v", err)
					return
				}
				origPath := alwaysDirectListFile
				newPath := alwaysDirectListFile + ".new"
				if err := ioutil.WriteFile(newPath, b, 0644); err != nil {
					logf("write %s error: %v", newPath, err)
					return
				}
				if err := os.Rename(newPath, origPath); err != nil {
					logf("rename %s -> %s error: %v", newPath, origPath, err)
				}
			}()
		}
	}
}

func netIPSlicesEquals(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for _, i := range a {
		for _, j := range b {
			if !j.Equal(i) {
				return false
			}
		}
	}
	return true
}

func (f *FakeDns) ipv4toInt(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func (f *FakeDns) parseAcl(filename string) []*iprange.IPV4Range {
	var ipranges []*iprange.IPV4Range

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var bypassList bool
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), " ")
		if line == "" {
			continue
		}
		if line[0] == '[' {
			if line == "[bypass_list]" {
				bypassList = true
			} else {
				bypassList = false
			}
			continue
		}
		if !bypassList {
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err == nil {
			ipranges = append(ipranges, &iprange.IPV4Range{Start: f.ipv4toInt(ipnet.IP), IPNet: ipnet})
		}
	}

	return ipranges
}

func (f *FakeDns) ShouldDirectConnect(ip net.IP) bool {
	res := false
	for _, r := range f.alwaysDirectList {
		r.RLock()
		for _, directIp := range r.IPs {
			if ip.Equal(directIp) {
				res = true
				break
			}
		}
		r.RUnlock()
		if res {
			break
		}
	}
	if res {
		return res
	}
	return iprange.IPv4Contains(f.aclRanges, ip)
}

func (f *FakeDns) insertFakeDnsRecord(ip string, domain string) {
	f.mappingMutex.Lock()
	f.insertFakeDnsRecordWithoutLock(ip, domain)
	f.mappingMutex.Unlock()
}

func (f *FakeDns) insertFakeDnsRecordWithoutLock(ip string, domain string) {
	if ip != "" {
		f.mapping[ip] = domain
		oldIp, ok := f.mapping[domain]
		if !ok || oldIp == "" {
			fmt.Fprintln(f.cacheFile, domain, "1")
		}
		logf("fakeDns insert: %s -> %s", domain, ip)
	} else {
		fmt.Fprintln(f.cacheFile, domain, "0")
		logf("fakeDns bypass: %s", domain)
	}
	f.mapping[domain] = ip
}

func (f *FakeDns) newFakeIp() string {
	newIpInt := atomic.AddUint32(&f.fakeDnsIp4, 1)
	newIpBytes := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(newIpBytes, newIpInt)
	return net.IP(newIpBytes).String()
}

func (f *FakeDns) Replace(orig socks.Addr) socks.Addr {
	ip, port, _ := net.SplitHostPort(orig.String())
	if net.ParseIP(ip) == nil {
		return orig
	}
	f.mappingMutex.RLock()
	domain := f.mapping[ip]
	f.mappingMutex.RUnlock()
	if domain == "" {
		return orig
	}
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	addr := socks.ParseAddr(net.JoinHostPort(domain, port))
	if addr == nil {
		return orig
	}
	logf("fakeDns replace: %s -> %s", orig, addr)
	return addr
}

func failedDnsMsg(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	return m
}

func fakeRespDnsMsg(r *dns.Msg, ips []string) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	m.CheckingDisabled = true
	q := r.Question[0]
	m.Question = []dns.Question{q}
	rrs := make([]dns.RR, len(ips))
	for i, ip := range ips {
		rrs[i] = &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: q.Qtype,
				Ttl:    3600,
				Class:  dns.ClassINET,
			},
			A: net.ParseIP(ip),
		}
	}
	m.Answer = rrs
	return m
}

func directLookup(domain string, dnsSrv []string) ([]string, error) {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	logf("direct lookup %s @%s", domain, dnsSrv)
	m := new(dns.Msg)
	m.Id = uint16(atomic.AddUint32(&directLookupId, 1))
	m.Opcode = dns.OpcodeQuery
	m.CheckingDisabled = true
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{
			Name:   domain,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	}
	resp, err := directQueryWithMsg(m, dnsSrv)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, &DnsError{resp.Rcode}
	}
	var ips []string
	for _, answer := range resp.Answer {
		if dnsA, ok := answer.(*dns.A); ok {
			ips = append(ips, dnsA.A.String())
		}
	}
	return ips, nil
}

func directQueryWithMsg(req *dns.Msg, dnsSrvs []string) (resp *dns.Msg, err error) {
	for _, dnsSrv := range dnsSrvs {
		resp, err = func() (*dns.Msg, error) {
			co := new(dns.Conn)
			if co.Conn, err = net.DialTimeout("udp4", dnsSrv, dnsTimeout); err != nil {
				return nil, err
			}
			defer co.Close()
			co.SetWriteDeadline(time.Now().Add(dnsTimeout))
			if err = co.WriteMsg(req); err != nil {
				return nil, err
			}
			co.SetReadDeadline(time.Now().Add(dnsTimeout))
			return co.ReadMsg()

		}()
		if err == nil {
			if resp.Rcode != dns.RcodeServerFailure {
				break
			}
		}
	}
	return resp, err
}

func (f *FakeDns) refreshProbeDnsSrv() error {
	const nsCachePath = "fakedns.ns"

	fetchRemote := func() error {
		const probeSrvCap = 2
		var (
			probeDnsSrvCh = make(chan string, probeSrvCap)

			probeSrvCnt uint32

			wg = &sync.WaitGroup{}

			probeTLDs = []string{"hk", "kr", "jp"}
		)

		for _, probeTLD := range probeTLDs {
			wg.Add(1)
			go func(probeTLD string) {
				defer wg.Done()
				m := new(dns.Msg)
				m.Id = uint16(atomic.AddUint32(&directLookupId, 1))
				m.Opcode = dns.OpcodeQuery
				m.CheckingDisabled = true
				m.RecursionDesired = true
				m.Question = []dns.Question{
					{
						Name:   probeTLD + ".",
						Qtype:  dns.TypeNS,
						Qclass: dns.ClassINET,
					},
				}
				resp, err := directQueryWithMsg(m, f.chinaDNS)
				if err != nil {
					logf("query NS %s error: %v", probeTLD, err)
					return
				}
				if resp.Rcode != dns.RcodeSuccess {
					logf("query NS %s, rcode=%v", probeTLD, dns.RcodeToString[resp.Rcode])
					return
				}
				var probeNameServers []string
				for _, answer := range resp.Answer {
					if ns, ok := answer.(*dns.NS); ok {
						probeNameServers = append(probeNameServers, ns.Ns)
					}
				}
				if len(probeNameServers) == 0 {
					logf("query NS %s but got none", probeTLD)
					return
				}
				logf("query NS %s: %v", probeTLD, probeNameServers)

				for _, s := range probeNameServers {
					wg.Add(1)
					go func(s string) {
						defer wg.Done()
						if atomic.LoadUint32(&probeSrvCnt) > probeSrvCap {
							return
						}
						ips, err := directLookup(s, f.chinaDNS)
						if err != nil {
							logf("lookup %s: %v", s, err)
							return
						}
						for _, ip := range ips {
							wg.Add(1)
							go func(ip string) {
								defer wg.Done()
								if atomic.LoadUint32(&probeSrvCnt) > probeSrvCap {
									return
								}
								ip += ":53"
								_, err := directLookup("www.baidu.com", []string{ip})
								logf("probe server %s return: %v", ip, err)
								if err != nil {
									if _, ok := err.(*DnsError); ok {
										if atomic.AddUint32(&probeSrvCnt, 1) <= probeSrvCap {
											probeDnsSrvCh <- ip
										}
									}
								}
							}(ip)
							time.Sleep(20 * time.Millisecond)
						}
					}(s)
					time.Sleep(20 * time.Millisecond)
				}
			}(probeTLD)
		}

		wgCh := make(chan struct{})
		go func() {
			wg.Wait()
			close(wgCh)
		}()
		ips := make([]string, 0, probeSrvCap)
		for i := 0; i < probeSrvCap; i++ {
			var ip string
			select {
			case ip = <-probeDnsSrvCh:
			case <-wgCh:
				select {
				case ip = <-probeDnsSrvCh:
				default:
					i = probeSrvCap
				}
			}
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		logf("probe dns: %v", ips)
		changed := false
		f.probeDNSMutex.Lock()
		if len(f.probeDNS) != len(ips) {
			changed = true
		} else {
			for _, a := range f.probeDNS {
				found := false
				for _, b := range ips {
					if a == b {
						found = true
						break
					}
				}
				if !found {
					changed = true
					break
				}
			}
		}
		if changed {
			f.probeDNS = ips
		}
		f.probeDNSMutex.Unlock()
		if changed {
			ioutil.WriteFile(nsCachePath, []byte(strings.Join(ips, "\n")), 0600)
		}
		return nil
	}

	var ips []string
	nsBytes, _ := ioutil.ReadFile(nsCachePath)
	nsStr := string(nsBytes)
	for _, s := range strings.Split(nsStr, "\n") {
		if host, port, err := net.SplitHostPort(s); err == nil {
			if net.ParseIP(host) != nil {
				if _, err := strconv.Atoi(port); err == nil {
					ips = append(ips, s)
				}
			}
		}
	}
	var err error
	if len(ips) > 0 {
		f.probeDNSMutex.Lock()
		f.probeDNS = ips
		f.probeDNSMutex.Unlock()
		logf("probe name server load from cache: %v", ips)
	} else {
		err = fetchRemote()
	}
	go func() {
		if info, err := os.Stat(nsCachePath); err == nil {
			delta := time.Now().Sub(info.ModTime())
			if delta < 0 {
				delta = 0
			}
			delta = time.Hour - delta
			if delta > 0 {
				time.Sleep(delta)
			}
		}
		for {
			logf("fetchRemote: %v", fetchRemote())
			time.Sleep(time.Hour)
		}
	}()
	return err
}
