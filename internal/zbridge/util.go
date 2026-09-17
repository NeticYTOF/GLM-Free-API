package zbridge

import (
	"errors"
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ============================================================================
// INITIALIZATION
// ============================================================================

func init() {
    // Initialise URL safe-character table for custom URL encoder
    for i := 0; i < 256; i++ {
        c := byte(i)
        if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            c == '-' || c == '_' || c == '.' || c == '~' {
            baseSafeTable[i] = true
        }
    }
}

// ============================================================================
// LOGGING — silent unless --verbose
// ============================================================================

func logError(msg string) {
    if !verbose {
        return
    }
    ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
    logMu.Lock()
    fmt.Fprintf(os.Stderr, "[%s] ERROR: %s\n", ts, msg)
    logMu.Unlock()
}

func logInfo(msg string) {
    if !verbose {
        return
    }
    ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
    logMu.Lock()
    fmt.Fprintf(os.Stderr, "[%s] INFO: %s\n", ts, msg)
    logMu.Unlock()
}

// ============================================================================
// BUFFER POOLS — eliminate GC pressure on hot paths
// ============================================================================

var bufPool = sync.Pool{
    New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 4096)) },
}

var zlibWriterPool = sync.Pool{
    New: func() interface{} {
        w, _ := zlib.NewWriterLevel(io.Discard, zlib.DefaultCompression)
        return w
    },
}

// ============================================================================
// HTTP CLIENTS — pooled connections, HTTP/2, keep-alive
// ============================================================================

// Optimised client for Aliyun captcha API calls
var aliyunHTTPClient = &http.Client{
    Transport: newPacedTransport(&http.Transport{
        MaxIdleConns:          100,
        MaxIdleConnsPerHost:   20,
        MaxConnsPerHost:       20,
        IdleConnTimeout:       90 * time.Second,
        TLSHandshakeTimeout:   10 * time.Second,
        ExpectContinueTimeout: 1 * time.Second,
        ResponseHeaderTimeout: 15 * time.Second,
        ForceAttemptHTTP2:     true,
    }),
    Timeout: 30 * time.Second,
}

// TLS FINGERPRINT SPOOFING — uTLS with Chrome ClientHello
// Aliyun ESA WAF does JA3 fingerprinting; Go's default TLS is blocked.
// ============================================================================

// dialUTLS creates a TLS connection using Chrome's ClientHello fingerprint.
// Respects HTTP_PROXY/HTTPS_PROXY environment variables for proxy tunneling.
func dialUTLS(ctx context.Context, network, addr string) (net.Conn, error) {
    host, _, err := net.SplitHostPort(addr)
    if err != nil {
        return nil, err
    }

    dialer := &net.Dialer{
        Timeout:   15 * time.Second,
        KeepAlive: 30 * time.Second,
    }

    var rawConn net.Conn

    // Check for proxy (HTTP_PROXY / HTTPS_PROXY / ALL_PROXY)
    proxyStr := os.Getenv("HTTPS_PROXY")
    if proxyStr == "" {
        proxyStr = os.Getenv("HTTP_PROXY")
    }
    if proxyStr == "" {
        proxyStr = os.Getenv("ALL_PROXY")
    }
    if proxyStr == "" {
        proxyStr = os.Getenv("https_proxy")
    }
    if proxyStr == "" {
        proxyStr = os.Getenv("http_proxy")
    }
    if proxyStr == "" {
        proxyStr = os.Getenv("all_proxy")
    }

    if proxyStr != "" {
        // Parse proxy URL
        proxyURL, err := url.Parse(proxyStr)
        if err == nil && proxyURL.Host != "" {
            // Connect to proxy
            proxyConn, err := dialer.DialContext(ctx, "tcp", proxyURL.Host)
            if err != nil {
                return nil, fmt.Errorf("proxy connect: %w", err)
            }

            // Send CONNECT request for HTTPS tunneling
            connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
            _, err = proxyConn.Write([]byte(connectReq))
            if err != nil {
                proxyConn.Close()
                return nil, fmt.Errorf("proxy CONNECT write: %w", err)
            }

            // Read CONNECT response
            br := bufio.NewReader(proxyConn)
            line, err := br.ReadString('\n')
            if err != nil {
                proxyConn.Close()
                return nil, fmt.Errorf("proxy CONNECT read: %w", err)
            }
            if !strings.Contains(line, "200") {
                proxyConn.Close()
                return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(line))
            }
            // Drain remaining headers
            for {
                line, err = br.ReadString('\n')
                if err != nil || strings.TrimSpace(line) == "" {
                    break
                }
            }

            // If bufio reader buffered extra data, unwrap it
            if br.Buffered() > 0 {
                buffered := make([]byte, br.Buffered())
                br.Read(buffered)
                rawConn = &concatConn{
                    Conn:   proxyConn,
                    buffer: buffered,
                }
            } else {
                rawConn = proxyConn
            }

            logInfo(fmt.Sprintf("[uTLS] Using proxy %s for %s", proxyURL.Host, addr))
        } else {
            rawConn, err = dialer.DialContext(ctx, network, addr)
            if err != nil {
                return nil, err
            }
        }
    } else {
        // Direct connection (no proxy)
        rawConn, err = dialer.DialContext(ctx, network, addr)
        if err != nil {
            return nil, err
        }
    }

    // uTLS config — advertise HTTP/1.1 only to avoid HTTP/2 fingerprinting
    config := &utls.Config{
        ServerName:         host,
        NextProtos:         []string{"http/1.1"},
        InsecureSkipVerify: false,
    }

    // HelloChrome_Auto tracks the newest Chrome profile the uTLS version
    // implements. Pinning an explicit release (this was HelloChrome_120, from
    // late 2023) turns into a fingerprint no real visitor sends any more, and
    // Aliyun's WAF answers those with the 405 block page.
    uConn := utls.UClient(rawConn, config, utls.HelloChrome_Auto)

    if err := uConn.HandshakeContext(ctx); err != nil {
        rawConn.Close()
        return nil, err
    }

    return uConn, nil
}

// concatConn wraps a connection that has pre-buffered data from a bufio.Reader.
type concatConn struct {
    net.Conn
    buffer []byte
}

func (c *concatConn) Read(b []byte) (int, error) {
    if len(c.buffer) > 0 {
        n := copy(b, c.buffer)
        c.buffer = c.buffer[n:]
        return n, nil
    }
    return c.Conn.Read(b)
}

// Z.AI client with cookie jar + uTLS Chrome fingerprint
var zaiJar = &cookieJar{}

var zaiHTTPClient = &http.Client{
	Transport: newPacedTransport(zaiTransport()),
	Jar:       zaiJar,
}

// zaiTransport builds the HTTP client transport for the Z.AI upstream. By
// default it is a direct uTLS Chrome-fingerprint dialer. When ROUTING_URL is
// set (the shared routing port), it is replaced by a SOCKS5 transport that
// routes through the selected warmed exit IP so Z.AI only sees Tor.
func zaiTransport() http.RoundTripper {
	transport := &http.Transport{
		DialTLSContext:        dialUTLS,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		MaxConnsPerHost:       20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}

	// If ROUTING_URL is configured, use the shared routing port to dial
	// Z.AI through the shared Tor exit pool instead of direct. Keep-alives
	// are OFF for routed egress: every chat request dials fresh, so each
	// request is granted its own exit from the round-robin queue (strict
	// 1 request = 1 hop). Pooled sockets would pin multiple requests to
	// one exit and defeat the rotation.
	if routingURL != "" {
		transport.DialContext = sharedRoutingDialContext
		transport.DialTLSContext = sharedRoutingDialTLSContext
		transport.DisableKeepAlives = true
		transport.MaxIdleConnsPerHost = 0
	}

	return newPacedTransport(transport)
}

// routingExitCtxKey carries a pinned shared-pool exit through a request's
// context, so every dial that request makes uses the SAME exit (and the WAF
// cool targets exactly the exit that was blocked, never a neighbor's).
type routingExitCtxKey struct{}

// routedExit is an exit IP + its Tor circuit credential, pinned for one chat
// request's whole upstream lifetime.
type routedExit struct {
	ip   string
	cred string
}

// withRoutingExit returns ctx carrying the pinned exit for this request.
func withRoutingExit(ctx context.Context, ip, cred string) context.Context {
	return context.WithValue(ctx, routingExitCtxKey{}, routedExit{ip: ip, cred: cred})
}

// routingExitFromCtx returns the pinned exit, if the request carries one.
func routingExitFromCtx(ctx context.Context) (routedExit, bool) {
	re, ok := ctx.Value(routingExitCtxKey{}).(routedExit)
	return re, ok && re.cred != ""
}

// routedConn wraps a Tor-egress socket so its shared-pool slot is released
// back to the round-robin queue the moment the socket closes — exact
// grant/release pairing with no handler bookkeeping, so slots can never
// leak and the queue always rotates.
type routedConn struct {
	net.Conn
	exitIp   string
	released bool
	mu       sync.Mutex
}

func (c *routedConn) Close() error {
	c.mu.Lock()
	if !c.released {
		c.released = true
		ip := c.exitIp
		go releaseExitByIp(ip)
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

// releaseExitByIp hands one exit slot back to the shared pool. Fire-and-forget;
// the pool treats a release of an already-free slot as a no-op.
func releaseExitByIp(ip string) {
	if routingURL == "" || ip == "" {
		return
	}
	body, _ := json.Marshal(map[string]interface{}{"exitIp": ip})
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, routingURL+"/routing/release", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)
}

// resolveRoutingExit returns the exit this dial must use: the request-pinned
// one if present, else a fresh grant from the shared pool. The second return
// is the exit IP for release/cool reporting.
func resolveRoutingExit(ctx context.Context) (cred, exitIp string, err error) {
	if re, ok := routingExitFromCtx(ctx); ok {
		return re.cred, re.ip, nil
	}
	pick, perr := fetchRoutingPick()
	if perr != nil || !pick.OK || pick.Tor.Cred == "" {
		log.Printf("[ROUTING] pick failed (routingURL=%q): %v", routingURL, perr)
		return "", "", fmt.Errorf("[ROUTING] no exit available from shared pool (routingURL=%q)", routingURL)
	}
	log.Printf("[ROUTING] granted exit %s (provider %s)", pick.ExitIP, routingProvider)
	return pick.Tor.Cred, pick.ExitIP, nil
}

// sharedRoutingDialContext routes a plain TCP dial through the shared routing
// port so the upstream sees a warmed Tor exit IP instead of the host. There is
// NO direct fallback on failure: the whole point of the shared pool is that
// Z.AI only ever sees Tor — a silent direct dial would leak the host IP and
// get it WAF-blocked.
func sharedRoutingDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	creds, exitIp, err := resolveRoutingExit(ctx)
	if err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(addr)
	socksAddr := fmt.Sprintf("%s:%s", routingSockHost, routingSockPort)
	conn, err := net.DialTimeout("tcp", socksAddr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("[ROUTING] SOCKS5 dial %s: %w", socksAddr, err)
	}
	if err := socks5Connect(conn, host, port, creds); err != nil {
		conn.Close()
		releaseExitByIp(exitIp)
		return nil, fmt.Errorf("[ROUTING] SOCKS5 connect: %w", err)
	}
	return &routedConn{Conn: conn, exitIp: exitIp}, nil
}

// sharedRoutingDialTLSContext routes a TLS dial through the shared routing
// port, then runs the uTLS Chrome handshake over the pinned Tor circuit.
func sharedRoutingDialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	creds, exitIp, err := resolveRoutingExit(ctx)
	if err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(addr)
	socksAddr := fmt.Sprintf("%s:%s", routingSockHost, routingSockPort)
	conn, err := net.DialTimeout("tcp", socksAddr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("[ROUTING] SOCKS5 dial %s: %w", socksAddr, err)
	}
	if err := socks5Connect(conn, host, port, creds); err != nil {
		conn.Close()
		releaseExitByIp(exitIp)
		return nil, fmt.Errorf("[ROUTING] SOCKS5 connect: %w", err)
	}
	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         host,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: false,
	}, utls.HelloChrome_Auto)
	return &routedConn{Conn: uconn, exitIp: exitIp}, nil
}

// ============================================================================
// SHARED ROUTING PORT — SOCKS5 exit-IP creds + handshake
// ============================================================================

// waitForRoutingExit blocks until the shared pool hands out an exit (or the
// timeout elapses). Used at session bootstrap: the bridge must never do the
// guest handshake over a direct connection, so instead of failing it waits
// for the proxy's Tor pool to be warm.
func waitForRoutingExit(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		pick, err := fetchRoutingPick()
		if err == nil && pick.OK && pick.Tor.Cred != "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("shared pool gave no exit within %s", timeout)
		}
		time.Sleep(2 * time.Second)
	}
}

// coolRoutingExit tells the shared pool that exitIp hit a WAF block for
// retryInMs, so it is shelved for that provider and the next pick hops.
// The socket's own slot is still freed by its Close; cooling only shelves.
func coolRoutingExit(exitIp string, retryInMs int) {
	if routingURL == "" || exitIp == "" {
		return
	}
	body, _ := json.Marshal(map[string]interface{}{
		"exitIp":     exitIp,
		"provider":   routingProvider,
		"retryInMs":  retryInMs,
		"reason":     "waf_block",
	})
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, routingURL+"/routing/cool", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)
}

// routingPickT is the shape the shared routing port returns from /routing/pick.
type routingPickT struct {
	OK       bool `json:"ok"`
	Provider string `json:"provider"`
	ExitIP   string `json:"exitIp"`
	ID       string `json:"id"`
	Tor      struct {
		Host string `json:"host"`
		Port string `json:"port"`
		Cred string `json:"cred"`
	} `json:"tor"`
	Cooldowns  map[string]float64 `json:"cooldowns"`
	FailCount  int                `json:"failCount"`
	Reason     string `json:"reason"`
}

// fetchRoutingPick queries the shared routing port for the next warmed exit
// for the configured provider (glm by default). EVERY call is a fresh grant
// that advances the round-robin queue — deliberately never cached, so each
// dial (and therefore each request) hops to a different exit.
func fetchRoutingPick() (routingPickT, error) {
	// Use a plain HTTP client (not the zai one — avoid recursion through the
	// SOCKS dialer) to reach the local routing port.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(routingURL + "/routing/pick?provider=" + routingProvider)
	if err != nil {
		return routingPickT{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return routingPickT{}, fmt.Errorf("routing pick HTTP %d", resp.StatusCode)
	}
	var p routingPickT
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return routingPickT{}, err
	}
	return p, nil
}

// socks5Connect performs a SOCKS5 CONNECT handshake with username/password
// auth over the already-established TCP connection to the SOCKS5 proxy,
// tunneling to host:port. The username pins a specific Tor circuit (the
// proxy's agentForId uses "socks://<id>:tor@host:port"), so Z.AI sees the
// exit IP the shared pool handed out — never the host's real IP.
func socks5Connect(conn net.Conn, host, port, cred string) error {
	// Split "id:tor" into username/password. Tor isolates circuits by
	// username:password pair, which is how the shared pool pins exits.
	user, pass, ok := strings.Cut(cred, ":")
	if !ok || user == "" {
		return fmt.Errorf("socks5 cred malformed (want id:tor)")
	}

	// Greeting: SOCKS5, offer no-auth (0x00) AND username/password (0x02).
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	var gm [2]byte
	if _, err := io.ReadFull(conn, gm[:]); err != nil {
		return fmt.Errorf("socks5 greeting reply: %w", err)
	}
	if gm[0] != 0x05 {
		return fmt.Errorf("socks5 bad version: %d", gm[0])
	}
	switch gm[1] {
	case 0x00:
		// Server picked no-auth (Tor won't when auth is offered, but accept it).
	case 0x02:
		// Username/password subnegotiation (RFC 1929): VER(1) ULEN UNAME PLEN PASSWD
		ub, pb := []byte(user), []byte(pass)
		if len(ub) > 255 || len(pb) > 255 {
			return fmt.Errorf("socks5 cred too long")
		}
		authReq := make([]byte, 0, 3+len(ub)+len(pb))
		authReq = append(authReq, 0x01, byte(len(ub)))
		authReq = append(authReq, ub...)
		authReq = append(authReq, byte(len(pb)))
		authReq = append(authReq, pb...)
		if _, err := conn.Write(authReq); err != nil {
			return fmt.Errorf("socks5 auth write: %w", err)
		}
		var ar [2]byte
		if _, err := io.ReadFull(conn, ar[:]); err != nil {
			return fmt.Errorf("socks5 auth reply: %w", err)
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("socks5 auth rejected (status %d)", ar[1])
		}
	default:
		return fmt.Errorf("socks5 no acceptable auth method: 0x%02x", gm[1])
	}

	// CONNECT request: VER CMD RSV ATYP(DOMAIN) LEN HOST PORT
	hb := []byte(host)
	if len(hb) > 255 {
		return fmt.Errorf("socks5 host too long")
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hb))}
	req = append(req, hb...)
	portNum := portToUint16(port)
	req = append(req, byte(portNum>>8), byte(portNum&0xFF))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect request: %w", err)
	}
	// Reply head: VER REP RSV ATYP
	var rh [4]byte
	if _, err := io.ReadFull(conn, rh[:]); err != nil {
		return fmt.Errorf("socks5 connect reply: %w", err)
	}
	if rh[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: code %d", rh[1])
	}
	// Consume the bound address per ATYP so the stream is exactly at the
	// payload boundary when the handshake returns.
	switch rh[3] {
	case 0x01: // IPv4
		var buf [6]byte // 4 addr + 2 port
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return fmt.Errorf("socks5 addr v4: %w", err)
		}
	case 0x03: // domain: 1 len + n domain + 2 port
		var lb [1]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return fmt.Errorf("socks5 addr dom len: %w", err)
		}
		dom := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(conn, dom); err != nil {
			return fmt.Errorf("socks5 addr dom: %w", err)
		}
	case 0x04: // IPv6
		var buf [18]byte // 16 addr + 2 port
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return fmt.Errorf("socks5 addr v6: %w", err)
		}
	}
	return nil
}

func portToUint16(port string) uint16 {
	n, err := strconv.Atoi(port)
	if err != nil {
		return 443
	}
	if n < 0 || n > 65535 {
		return 443
	}
	return uint16(n)
}

// ============================================================================
// COOKIE JAR — minimal implementation, thread-safe
// ============================================================================

type cookieEntry struct {
    name   string
    value  string
    domain string
    path   string
}

type cookieJar struct {
    mu      sync.Mutex
    cookies []cookieEntry
}

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
    j.mu.Lock()
    defer j.mu.Unlock()
    for _, c := range cookies {
        filtered := j.cookies[:0]
        for _, e := range j.cookies {
            if e.name == c.Name && e.domain == c.Domain && e.path == c.Path {
                continue
            }
            filtered = append(filtered, e)
        }
        j.cookies = filtered
        j.cookies = append(j.cookies, cookieEntry{
            name:   c.Name,
            value:  c.Value,
            domain: c.Domain,
            path:   c.Path,
        })
    }
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
    j.mu.Lock()
    defer j.mu.Unlock()
    var out []*http.Cookie
    for _, e := range j.cookies {
        out = append(out, &http.Cookie{
            Name:   e.name,
            Value:  e.value,
            Domain: e.domain,
            Path:   e.path,
        })
    }
    return out
}

// ============================================================================
// WARM-UP — acquire acw_tc anti-bot cookies before API calls
// ============================================================================

func warmupCookies() error {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    req, err := http.NewRequestWithContext(ctx, "GET", BASE_URL, nil)
    if err != nil {
        return err
    }
    req.Header.Set("User-Agent", zaiUserAgent)
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.9")
    req.Header.Set("sec-ch-ua", `"Not=A?Brand";v="99", "Brave";v="151", "Chromium";v="151"`)
    req.Header.Set("sec-ch-ua-mobile", "?0")
    req.Header.Set("sec-ch-ua-platform", `"Windows"`)

    resp, err := zaiHTTPClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    io.Copy(io.Discard, resp.Body)

    if config.Logging.Level == "debug" {
        cookies := zaiJar.Cookies(req.URL)
        for _, c := range cookies {
            v := c.Value
            if len(v) > 20 {
                v = v[:20]
            }
            log.Printf("[Warmup] Cookie: %s=%s...", c.Name, v)
        }
    }

    return nil
}

func minInt(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// 
// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func randomUUID() string {
    b := make([]byte, 16)
    rand.Read(b)
    b[6] = (b[6] & 0x0f) | 0x40
    b[8] = (b[8] & 0x3f) | 0x80
    return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func generateID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return hex.EncodeToString(b)
}

// ---------- UUID v4 — manual hex encoding, no fmt.Sprintf ----------

func generateUUID() string {
    var b [16]byte
    rand.Read(b[:])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80

    var dst [36]byte
    j := 0
    for i := 0; i < 16; i++ {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            dst[j] = '-'
            j++
        }
        dst[j] = hexLower[b[i]>>4]
        dst[j+1] = hexLower[b[i]&0xF]
        j += 2
    }
    return string(dst[:])
}

// ---------- Timestamp helpers ----------

func getTimestampUTC() string {
    return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func currentTimeMillis() int64 {
    return time.Now().UnixMilli()
}

// ---------- Token estimation ----------

func estimateTokens(text string) int {
    if text == "" {
        return 0
    }
    return (len(text) + 3) / 4
}

// ---------- Message helpers ----------

func getMessageContent(content json.RawMessage) string {
    if len(content) == 0 {
        return ""
    }
    var s string
    if err := json.Unmarshal(content, &s); err == nil {
        return s
    }
    var arr []interface{}
    if err := json.Unmarshal(content, &arr); err == nil {
        var texts []string
        for _, item := range arr {
            switch v := item.(type) {
            case string:
                texts = append(texts, v)
            case map[string]interface{}:
                t, _ := v["type"].(string)
                if t == "text" {
                    if txt, ok := v["text"].(string); ok {
                        texts = append(texts, txt)
                    }
                }
            }
        }
        return strings.Join(texts, "\n")
    }
    return string(content)
}

func messagesToPrompt(messages []Message) string {
    var sb strings.Builder
    for _, msg := range messages {
        content := getMessageContent(msg.Content)
        sb.WriteString(content)
        sb.WriteString("\n\n")
    }
    return strings.TrimSpace(sb.String())
}

func boolPtr(b bool) *bool { return &b }

// ============================================================================
// URL ENCODING — custom lookup table, zero allocations for safe chars
// ============================================================================

const hexUpper = "0123456789ABCDEF"
const hexLower = "0123456789abcdef"

var baseSafeTable [256]bool

func urlEncode(s string, safe string) string {
    var safeTable [256]bool
    safeTable = baseSafeTable
    for i := 0; i < len(safe); i++ {
        safeTable[safe[i]] = true
    }

    var b strings.Builder
    b.Grow(len(s)*3 + 16)
    for i := 0; i < len(s); i++ {
        c := s[i]
        if safeTable[c] {
            b.WriteByte(c)
        } else {
            b.WriteByte('%')
            b.WriteByte(hexUpper[c>>4])
            b.WriteByte(hexUpper[c&0x0F])
        }
    }
    return b.String()
}

func fromHex(c byte) byte {
    switch {
    case c >= '0' && c <= '9':
        return c - '0'
    case c >= 'A' && c <= 'F':
        return c - 'A' + 10
    case c >= 'a' && c <= 'f':
        return c - 'a' + 10
    default:
        return 0
    }
}

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

func base64Encode(data []byte) string {
    return base64.StdEncoding.EncodeToString(data)
}

func hmacSHA1(key, msg []byte) []byte {
    h := hmac.New(sha1.New, key)
    h.Write(msg)
    return h.Sum(nil)
}

func base64Decode(s string) ([]byte, error) {
    if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
        return b, nil
    }
    if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
        return b, nil
    }
    if b, err := base64.URLEncoding.DecodeString(s); err == nil {
        return b, nil
    }
    if b, err := base64.StdEncoding.DecodeString(s); err == nil {
        return b, nil
    }
    if b, err := base64.StdEncoding.DecodeString(s + "=="); err == nil {
        return b, nil
    }
    if b, err := base64.URLEncoding.DecodeString(s + "=="); err == nil {
        return b, nil
    }
    return nil, errors.New("base64 decode failed")
}

// ============================================================================
// JSON MARSHALING — disables HTML escaping, uses pooled buffer
// ============================================================================

func jsonMarshal(v interface{}) ([]byte, error) {
    buf := bufPool.Get().(*bytes.Buffer)
    buf.Reset()
    enc := json.NewEncoder(buf)
    enc.SetEscapeHTML(false)
    if err := enc.Encode(v); err != nil {
        bufPool.Put(buf)
        return nil, err
    }
    raw := buf.Bytes()
    result := make([]byte, len(raw)-1)
    copy(result, raw)
    bufPool.Put(buf)
    return result, nil
}

