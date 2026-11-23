//go:build p0system && windows

package engine

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A guest-local STUN Binding server. Reply only to valid requests. Each run
// has its own port so a late packet from the control cannot affect the result.
func guestSTUN(t *testing.T) (string, *atomic.Uint32) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var ip net.IP
	for _, address := range addresses {
		entry, ok := address.(*net.IPNet)
		if ok && entry.IP.To4() != nil && entry.IP.IsPrivate() {
			ip = entry.IP.To4()
			break
		}
	}
	if ip == nil {
		t.Fatal("Expected a disposable guest IPv4 interface")
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	count := new(atomic.Uint32)
	go func() {
		var b [2048]byte
		for {
			n, peer, err := socket.ReadFromUDP(b[:])
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint16(b[:2]) != 1 || int(binary.BigEndian.Uint16(b[2:4])) != n-20 || binary.BigEndian.Uint32(b[4:8]) != 0x2112a442 {
				continue
			}
			count.Add(1)
			var reply [32]byte
			copy(reply[:20], b[:20])
			binary.BigEndian.PutUint16(reply[:2], 0x0101)
			binary.BigEndian.PutUint16(reply[2:4], 12)
			binary.BigEndian.PutUint16(reply[20:22], 0x0020)
			binary.BigEndian.PutUint16(reply[22:24], 8)
			reply[25] = 1
			binary.BigEndian.PutUint16(reply[26:28], uint16(peer.Port)^0x2112)
			binary.BigEndian.PutUint32(reply[28:], binary.BigEndian.Uint32(peer.IP.To4())^0x2112a442)
			socket.WriteToUDP(reply[:], peer)
		}
	}()
	return socket.LocalAddr().String(), count
}

func stunObserverReady(t *testing.T, address string) bool {
	t.Helper()
	conn, err := net.DialTimeout("udp4", address, time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	var packet [20]byte
	packet[1] = 1
	binary.BigEndian.PutUint32(packet[4:8], 0x2112a442)
	if _, err = rand.Read(packet[8:]); err != nil {
		return false
	}
	if _, err = conn.Write(packet[:]); err != nil {
		return false
	}
	var reply [32]byte
	n, err := conn.Read(reply[:])
	return err == nil && n == 32 && binary.BigEndian.Uint16(reply[:2]) == 0x101 && string(reply[8:20]) == string(packet[8:])
}

func TestInstalledChromeWebRTC(t *testing.T) {
	testChromeWebRTC(t, true, false)
}

func TestChromeWebRTCPrivacy(t *testing.T) {
	testChromeWebRTC(t, false, false)
}

func TestChromeWithTemporaryDNSBlock(t *testing.T) {
	testChromeWebRTC(t, false, true)
}

func testChromeWebRTC(t *testing.T, installed, blockSystemDNS bool) {
	recoveryGuest(t)
	if installed && os.Getenv("PH_GUEST_INSTALLED_CHROME") != "1" {
		t.Fatal("Fresh MSI Chrome installation required")
	}
	root := `C:\P0Lab\.local\p0`
	chrome := `C:\Program Files\Google\Chrome\Application\chrome.exe`
	if !installed {
		prepareCapsuleFixtures(t)
		copyCapsuleChrome(t)
		chrome = filepath.Join(capsuleAppDir, "chrome", "chrome.exe")
	}
	guardian := filepath.Join(root, "bin", "proxy-harbor-guardian.exe")
	checks := map[string]bool{}
	report := map[string]any{"scope": "Chrome 157 guest candidate: browser DNS over the TLS proxy, isolated default-DNS observer, repeated HTTPS fetches, IPv4 STUN and completed ICE gathering. Arbitrary child-service DNS and TURN/media workflows remain outside this test.", "checks": checks}
	t.Cleanup(func() {
		if !t.Failed() && report["guestCertificateRemoved"] == true {
			report["cleanup"] = "verified"
		} else {
			report["cleanup"] = "not_verified"
		}
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(filepath.Join(root, "managed-webrtc-report.json"), data, 0600)
	})
	check := func(name string, ok bool) {
		t.Helper()
		checks[name] = ok
		if !ok {
			t.Errorf("WebRTC: %s", name)
		}
	}
	controlAddr, controlCount := guestSTUN(t)
	wire := dnsCoverageObserver(t)
	ps := func(script string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command", "$ErrorActionPreference='Stop';"+script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	const nrptOwner = "ProxyHarbor.P0.ChromeDNS"
	if err := ps(`if(@(Get-DnsClientNrptRule|Where-Object {$_.Namespace -contains '.p0-dns-audit.invalid'}).Count){throw 'Observation namespace already configured'};Add-DnsClientNrptRule -Namespace '.p0-dns-audit.invalid' -NameServers '127.0.0.1' -DisplayName '` + nrptOwner + `'|Out-Null`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := ps(`Get-DnsClientNrptRule|Where-Object {$_.DisplayName -eq '` + nrptOwner + `' -and @($_.Namespace).Count -eq 1 -and $_.Namespace -contains '.p0-dns-audit.invalid'}|ForEach-Object {Remove-DnsClientNrptRule -Name $_.Name -Force};if(@(Get-DnsClientNrptRule|Where-Object {$_.DisplayName -eq '` + nrptOwner + `'}).Count){throw 'NRPT cleanup failed'}`)
		check("dns_observer_configuration_removed", err == nil)
	})
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	dnsHost := fmt.Sprintf("%x.p0-dns-audit.invalid", nonce)
	controlHost := "resolver-" + dnsHost
	addresses, lookupErr := net.DefaultResolver.LookupIP(context.Background(), "ip4", controlHost)
	check("system_dns_observer_positive", lookupErr == nil && len(addresses) > 0 && len(wire(controlHost)) > 0)
	if blockSystemDNS {
		guard := exec.Command(filepath.Join(root, "bin", "dns-block-lab.exe"))
		input, err := guard.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := guard.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err = guard.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			input.Close()
			check("temporary_dns_guard_exited", guard.Wait() == nil)
			name := "restored-" + dnsHost
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
			check("system_dns_restored_after_chrome", err == nil && len(addresses) > 0 && len(wire(name)) > 0)
		})
		line, err := bufio.NewReader(output).ReadBytes('\n')
		var ready struct {
			Ready bool
			Error uint32
		}
		if err != nil || json.Unmarshal(line, &ready) != nil || !ready.Ready || ready.Error != 0 {
			t.Fatalf("DNS guard preflight: %s %v", line, err)
		}
		name := "blocked-" + dnsHost
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
		cancel()
		check("system_dns_blocked_while_chrome_active", err != nil && len(addresses) == 0 && len(wire(name)) == 0)
	}
	var dnsRequests atomic.Uint32
	managedAddr, managedCount := guestSTUN(t)
	type result struct{ run, phase, raw string }
	results := make(chan result, 16)
	page := func(req *http.Request, w io.Writer) {
		if strings.EqualFold(req.Host, "control-"+dnsHost) || strings.EqualFold(req.Host, "managed-"+dnsHost) {
			dnsRequests.Add(1)
			fmt.Fprint(w, "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			return
		}
		if req.URL.Path == "/signal" {
			q := req.URL.Query()
			select {
			case results <- result{q.Get("run"), q.Get("phase"), q.Get("raw")}:
			default:
			}
			fmt.Fprint(w, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
			return
		}
		run, addr := "managed", managedAddr
		if req.URL.Path == "/control" {
			run, addr = "control", controlAddr
		}
		if req.URL.Path != "/" && req.URL.Path != "/control" {
			fmt.Fprint(w, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
		body := fmt.Sprintf(`<!doctype html><script>
(async () => {
  const signal = (phase, raw=0) => fetch('/signal?run=%s&phase='+phase+'&raw='+raw);
  try {
    for (let i=0;i<2;i++) {
      const response = await fetch('https://%s/a?i='+i);
      if(await response.text()!=='ok') throw new Error('DNS target failed');
    }
    const pc = new RTCPeerConnection({iceServers:[{urls:'stun:%s'}]});
    pc.createDataChannel('p0');
    let raw = 0;
    pc.onicecandidate = e => {
      if (e.candidate && (e.candidate.type==='host' || [e.candidate.address,e.candidate.relatedAddress].some(a=>a && (/^[0-9.]+$/.test(a) || a.includes(':') || a.endsWith('.local'))))) raw++;
    };
    const finished = new Promise(resolve => {
      pc.onicegatheringstatechange = () => {if(pc.iceGatheringState==='complete') resolve('complete')};
      setTimeout(()=>resolve('deadline'),12000);
    });
    await signal('started');
    await pc.setLocalDescription(await pc.createOffer());
    await signal(await finished,raw);
    pc.close();
  } catch { await signal('error'); }
})();
</script>`, run, run+"-"+dnsHost, addr)
		fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}
	proxy, _, _ := managedExitFixture(t, report, page, nil)
	for _, run := range []string{"control", "managed"} {
		var cmd *exec.Cmd
		var folder string
		if run == "control" {
			cmd = exec.Command(chrome, "--headless=new", "--no-first-run", "--disable-gpu", "--disable-background-networking", "--user-data-dir="+t.TempDir(), "--proxy-server=http://"+proxy, "https://api.ipify.org/control")
		} else {
			check("managed_stun_observer_positive_before", stunObserverReady(t, managedAddr))
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				t.Fatal(err)
			}
			id := fmt.Sprintf("%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
			folder = filepath.Join(root, "sessions", id)
			if err := os.MkdirAll(folder, 0700); err != nil {
				t.Fatal(err)
			}
			owner := guestProxyEndpoint(t, "131.103.130.202", os.Getpid())
			_, port, _ := net.SplitHostPort(proxy)
			request := fmt.Sprintf("PH2\n%s\n%d\n%d\n%s\nchrome-user\n1\n%s %d %d\n%s\n", id, owner.PID, owner.Created, port, owner.IPv4, owner.PID, owner.Created, chrome)
			if err := os.WriteFile(filepath.Join(folder, "request.txt"), []byte(request), 0600); err != nil {
				t.Fatal(err)
			}
			cmd = exec.Command(guardian, "start", folder)
			cmd.Env = append(os.Environ(), "PH_GUEST_CHROME_MODE=hold")
		}
		before := managedCount.Load()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		outcome := "timeout"
		started := false
		raw := ""
		timeout := time.NewTimer(45 * time.Second)
	wait:
		for {
			select {
			case event := <-results:
				if event.run != run {
					continue
				}
				if event.phase == "started" {
					started = true
					continue
				}
				outcome, raw = event.phase, event.raw
				break wait
			case <-done:
				outcome = "exited"
				break wait
			case <-timeout.C:
				break wait
			}
		}
		timeout.Stop()
		if run == "control" {
			cmd.Process.Kill()
		} else {
			os.WriteFile(filepath.Join(folder, "stop"), []byte("stop"), 0600)
		}
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Fatal("Browser cleanup timeout")
		}
		report[run+"Outcome"] = outcome
		report[run+"LiteralCandidateCount"] = raw
		check(run+"_page_started_ice", started)
		if run == "control" {
			check("ordinary_chrome_sent_stun", controlCount.Load() > 0)
			continue
		}
		var final struct {
			State, Reason                              string
			FilterCount                                int
			BlockedFilterId, BlockedAt, BlockDirection string
			BlockedProtocol, BlockedRemotePort         int
		}
		data, err := os.ReadFile(filepath.Join(folder, "status.json"))
		if err != nil || json.Unmarshal(data, &final) != nil {
			t.Fatal("Missing guardian status")
		}
		check("managed_session_clean", final.State == "stopped" && final.FilterCount == 0)
		report["guardianFinal"] = final
		completedPrivately := outcome == "complete" && raw == "0" && final.Reason == "user_stopped"
		terminated := outcome == "exited" && final.Reason == "bypass_blocked" && final.BlockedAt != "" && final.BlockedFilterId != "" && final.BlockedFilterId != "0"
		report["iceGatheringCompleted"] = outcome == "complete"
		report["terminatedOnPolicyDrop"] = terminated
		check("managed_ice_contained", completedPrivately || terminated)
		check("managed_ice_gathering_completed_privately", completedPrivately)
		check("no_stun_packet_from_managed_browser", managedCount.Load() == before)
		check("managed_stun_observer_positive_after", stunObserverReady(t, managedAddr))
		check("browser_domain_reached_proxy_repeatedly", dnsRequests.Load() >= 4)
		check("browser_domain_absent_from_system_dns", len(wire("control-"+dnsHost)) == 0 && len(wire("managed-"+dnsHost)) == 0)
	}
}
