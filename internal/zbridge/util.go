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
	// Z.AI through the shared Tor exit pool instead of direct.
	if routingURL != "" {
		transport.DialContext = sharedRoutingDialContext
		transport.DialTLSContext = sharedRoutingDialTLSContext
	}

	return newPacedTransport(transport)
}

// sharedRoutingDialContext routes a plain TCP dial through the shared routing
// port so the upstream sees a warmed Tor exit IP instead of the host.
func sharedRoutingDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Ask the routing port for the current warmed exit for this provider
	// (glm by default). Fall back to direct if the port is unreachable.
	creds := routingExitCreds()
	if creds == "" {
		return (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, addr)
	}
	// Route through the shared Tor SOCKS5 endpoint (127.0.0.1:9050 by default,
	// matching the proxy's TOR_HOST/TOR_PORT) using the exit's circuit creds.
	host, port, _ := net.SplitHostPort(addr)
	socksAddr := fmt.Sprintf("%s:%s", routingSockHost, routingSockPort)
	conn, err := net.DialTimeout("tcp", socksAddr, 15*time.Second)
	if err != nil {
		logInfo("[ROUTING] SOCKS5 dial failed, falling back to direct: " + err.Error())
		return (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, addr)
	}
	// SOCKS5 CONNECT handshake with the exit's circuit credentials
	if err := socks5Connect(conn, host, port, creds); err != nil {
		conn.Close()
		logInfo("[ROUTING] SOCKS5 connect failed, falling back to direct: " + err.Error())
		return (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, addr)
	}
	return conn, nil
}

// sharedRoutingDialTLSContext routes a TLS dial through the shared routing port.
func sharedRoutingDialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	creds := routingExitCreds()
	if creds == "" {
		return dialUTLS(ctx, network, addr)
	}
	host, port, _ := net.SplitHostPort(addr)
	socksAddr := fmt.Sprintf("%s:%s", routingSockHost, routingSockPort)
	conn, err := net.DialTimeout("tcp", socksAddr, 15*time.Second)
	if err != nil {
		return dialUTLS(ctx, network, addr)
	}
	if err := socks5Connect(conn, host, port, creds); err != nil {
		conn.Close()
		return dialUTLS(ctx, network, addr)
	}
	// TLS handshake over the established tunnel
	return utls.UClient(conn, &utls.Config{
		ServerName:         host,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: false,
	}, utls.HelloChrome_Auto), nil
}

// ============================================================================
// SHARED ROUTING PORT — SOCKS5 exit-IP creds + handshake
// ============================================================================

// routingExitCreds returns the SOCKS5 circuit credentials for the current
// warmed exit IP, as a "<id>:tor" string, or "" when no routing port is
// configured or the pick is unavailable (direct egress in that case).
func routingExitCreds() string {
	if routingURL == "" {
		return ""
	}
	pick, err := fetchRoutingPick()
	if err != nil {
		return ""
	}
	if pick.Tor.Cred == "" {
		return ""
	}
	return pick.Tor.Cred
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

// fetchRoutingPick queries the shared routing port for the current warmed exit
// for the configured provider (glm by default). Cached briefly so every upstream
// dial doesn't re-query; the exit hops on cooldown anyway.
var routingPickCache routingPickT
var routingPickCacheMu sync.Mutex
var routingPickCacheAt time.Time

func fetchRoutingPick() (routingPickT, error) {
	routingPickCacheMu.Lock()
	defer routingPickCacheMu.Unlock()
	if !routingPickCacheAt.IsZero() && time.Since(routingPickCacheAt) < 5*time.Second {
		return routingPickCache, nil
	}
	// Use a plain HTTP client (not the zai one — avoid recursion through the
	// SOCKS dialer) to reach the local routing port.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(routingURL + "/routing/pick?provider=" + routingProvider)
	if err != nil {
		return routingPickCache, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return routingPickCache, fmt.Errorf("routing pick HTTP %d", resp.StatusCode)
	}
	var p routingPickT
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return routingPickCache, err
	}
	if p.OK {
		routingPickCache = p
		routingPickCacheAt = time.Now()
	}
	return p, nil
}

// socks5Connect performs a minimal SOCKS5 CONNECT handshake (no auth) over the
// already-established TCP connection to the SOCKS5 proxy, tunneling to
// host:port. The proxy (Tor) picks a circuit; the exit IP is the one the
// routing port handed out for this provider.
func socks5Connect(conn net.Conn, host, port, _ string) error {
	// Greeting: SOCKS5, no-auth.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("socks5 reply: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 no-auth rejected: %v", resp)
	}
	// CONNECT request: 0x05 0x01 (connect) 0x00 (reserved) 0x03 (domain)
	// len(host) host port(high)port(low)
	hb := []byte(host)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hb))}
	req = append(req, hb...)
	portNum := portToUint16(port)
	req = append(req, byte(portNum>>8), byte(portNum&0xFF))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect request: %w", err)
	}
	// Reply: version(1) + replycode(1) + reserved(1) + atyp(1) + addr + port
	var reply [5]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("socks5 connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: code %d", reply[1])
	}
	switch reply[3] {
	case 0x01: // IPv4: 4 bytes addr + 2 port
		var buf [6]byte
		_, _ = io.ReadFull(conn, buf[:])
	case 0x03: // domain: len(1) + domain + 2 port
		l := int(reply[4])
		var buf [1]byte
		if _, err := io.ReadFull(conn, buf[:]); err == nil {
			l = int(buf[0])
		}
		dom := make([]byte, l+2)
		_, _ = io.ReadFull(conn, dom)
	case 0x04: // IPv6: 16 bytes addr + 2 port
		var buf [18]byte
		_, _ = io.ReadFull(conn, buf[:])
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

