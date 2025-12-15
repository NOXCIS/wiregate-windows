/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 AmneziaWG. All Rights Reserved.
 */

package udptlspipe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	tls "github.com/refraction-networking/utls"
)

const (
	// WebSocket path used by udptlspipe (root path to match reference implementation)
	wsPath = "/"
	// Buffer size for UDP packets
	bufferSize = 65535
	// Dial timeout for connections
	dialTimeout = 30 * time.Second
	// Write timeout for WebSocket
	writeTimeout = 10 * time.Second
	// Ping interval for WebSocket keepalive
	pingInterval = 30 * time.Second
)

// Client represents a running udptlspipe client instance
type Client struct {
	ctx       context.Context
	cancel    context.CancelFunc
	localAddr string
	localPort int
	wg        sync.WaitGroup
	logger    Logger
}

// NewClient creates and starts a new udptlspipe client
// Returns the client and the local port it's listening on
func NewClient(
	destination string,
	password string,
	tlsServerName string,
	secure bool,
	proxyURL string,
	fingerprintProfile string,
	logger Logger,
) (*Client, int, error) {
	if logger == nil {
		logger = &DefaultLogger{}
	}

	// Default to okhttp if not specified
	if fingerprintProfile == "" {
		fingerprintProfile = "okhttp"
	}

	logger.Printf("udptlspipe: Starting client to %s (fingerprint: %s)", destination, fingerprintProfile)

	// Find a free port
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		setLastError(fmt.Errorf("failed to find free port: %w", err))
		logger.Printf("udptlspipe: Failed to find free port: %v", err)
		return nil, 0, err
	}
	addr := listener.LocalAddr().(*net.UDPAddr)
	localPort := addr.Port
	listenAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
	listener.Close()

	logger.Printf("udptlspipe: Listening on %s, destination %s", listenAddr, destination)

	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		ctx:       ctx,
		cancel:    cancel,
		localAddr: listenAddr,
		localPort: localPort,
		logger:    logger,
	}

	// Start the udptlspipe client in a goroutine
	client.wg.Add(1)
	go func() {
		defer client.wg.Done()
		err := runUdpTlsPipeClient(ctx, listenAddr, destination, password, tlsServerName, secure, proxyURL, fingerprintProfile, logger)
		if err != nil && ctx.Err() == nil {
			setLastError(err)
			logger.Printf("udptlspipe: Client error: %v", err)
		}
		logger.Printf("udptlspipe: Client stopped")
	}()

	logger.Printf("udptlspipe: Started with local port %d", localPort)
	return client, localPort, nil
}

// Stop stops the udptlspipe client
func (c *Client) Stop() {
	c.logger.Printf("udptlspipe: Stopping client")
	c.cancel()
	c.wg.Wait()
	c.logger.Printf("udptlspipe: Client stopped")
}

// LocalPort returns the local port the client is listening on
func (c *Client) LocalPort() int {
	return c.localPort
}

// LocalAddr returns the local address the client is listening on
func (c *Client) LocalAddr() string {
	return c.localAddr
}

// runUdpTlsPipeClient runs the udptlspipe client that listens for UDP packets
// and forwards them over a TLS WebSocket connection to the server.
func runUdpTlsPipeClient(
	ctx context.Context,
	listenAddr string,
	destination string,
	password string,
	tlsServerName string,
	secure bool,
	proxyURL string,
	fingerprintProfile string,
	logger Logger,
) error {
	// Parse destination to get host for TLS
	destHost, _, err := net.SplitHostPort(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %w", err)
	}

	// Use provided TLS server name or destination host
	serverName := tlsServerName
	if serverName == "" {
		serverName = destHost
	}

	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer udpConn.Close()

	logger.Printf("udptlspipe: UDP listener started on %s (fingerprint: %s)", listenAddr, fingerprintProfile)

	// Track client sessions (one WebSocket per UDP client)
	sessions := &sessionManager{
		sessions: make(map[string]*clientSession),
		logger:   logger,
	}
	defer sessions.closeAll()

	// Create a channel for stopping
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		udpConn.Close()
		close(done)
	}()

	buf := make([]byte, bufferSize)
	for {
		select {
		case <-done:
			return nil
		default:
		}

		// Set read deadline to allow checking for context cancellation
		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			logger.Printf("udptlspipe: UDP read error: %v", err)
			continue
		}

		// Get or create session for this client
		session := sessions.getOrCreate(clientAddr.String(), func() *clientSession {
			return newClientSession(
				ctx,
				clientAddr,
				udpConn,
				destination,
				serverName,
				password,
				secure,
				proxyURL,
				fingerprintProfile,
				logger,
			)
		})

		if session == nil {
			continue
		}

		// Send data through WebSocket
		data := make([]byte, n)
		copy(data, buf[:n])
		session.send(data)
	}
}

// sessionManager manages multiple client sessions
type sessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*clientSession
	logger   Logger
}

func (m *sessionManager) getOrCreate(key string, create func() *clientSession) *clientSession {
	m.mu.RLock()
	session, ok := m.sessions[key]
	m.mu.RUnlock()

	if ok && session.isAlive() {
		return session
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	session, ok = m.sessions[key]
	if ok && session.isAlive() {
		return session
	}

	// Create new session
	session = create()
	if session != nil {
		m.sessions[key] = session
	}
	return session
}

func (m *sessionManager) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, session := range m.sessions {
		session.close()
	}
	m.sessions = make(map[string]*clientSession)
}

// clientSession represents a single UDP client's WebSocket connection
type clientSession struct {
	ctx                context.Context
	cancel             context.CancelFunc
	clientAddr         *net.UDPAddr
	udpConn            *net.UDPConn
	wsConn             *websocket.Conn
	wsMu               sync.Mutex
	sendCh             chan []byte
	logger             Logger
	alive              bool
	aliveMu            sync.RWMutex
	fingerprintProfile string
}

func newClientSession(
	parentCtx context.Context,
	clientAddr *net.UDPAddr,
	udpConn *net.UDPConn,
	destination string,
	serverName string,
	password string,
	secure bool,
	proxyURL string,
	fingerprintProfile string,
	logger Logger,
) *clientSession {
	ctx, cancel := context.WithCancel(parentCtx)

	session := &clientSession{
		ctx:                ctx,
		cancel:             cancel,
		clientAddr:         clientAddr,
		udpConn:            udpConn,
		sendCh:             make(chan []byte, 256),
		logger:             logger,
		alive:              true,
		fingerprintProfile: fingerprintProfile,
	}

	// Connect to server in a goroutine
	go session.run(destination, serverName, password, secure, proxyURL)

	return session
}

func (s *clientSession) run(destination, serverName, password string, secure bool, proxyURL string) {
	defer func() {
		s.aliveMu.Lock()
		s.alive = false
		s.aliveMu.Unlock()
		s.cancel()
	}()

	// Build WebSocket URL
	wsURL := fmt.Sprintf("wss://%s%s", destination, wsPath)
	if password != "" {
		wsURL = fmt.Sprintf("%s?password=%s", wsURL, url.QueryEscape(password))
	}

	// Get the fingerprint profile's ClientHelloID and User-Agent (always in sync)
	clientHelloID, userAgent := GetFingerprintPair(s.fingerprintProfile)

	s.logger.Printf("udptlspipe: Using fingerprint profile: %s (ClientHello: %s)", s.fingerprintProfile, clientHelloID.Str())

	// Create custom dialer with utls support
	dialer := websocket.Dialer{
		HandshakeTimeout: dialTimeout,
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLSWithFingerprint(ctx, network, addr, serverName, secure, clientHelloID, s.logger)
		},
	}

	// Configure proxy if specified
	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err == nil {
			dialer.Proxy = http.ProxyURL(proxyURLParsed)
		} else {
			s.logger.Printf("udptlspipe: Invalid proxy URL: %v", err)
		}
	}

	s.logger.Printf("udptlspipe: Connecting to %s (SNI: %s, UA: %s)", destination, serverName, userAgent)

	// Connect to WebSocket server
	headers := http.Header{}
	headers.Set("User-Agent", userAgent)

	conn, _, err := dialer.DialContext(s.ctx, wsURL, headers)
	if err != nil {
		s.logger.Printf("udptlspipe: Failed to connect: %v", err)
		return
	}
	defer conn.Close()

	s.wsMu.Lock()
	s.wsConn = conn
	s.wsMu.Unlock()

	s.logger.Printf("udptlspipe: Connected to %s", destination)

	// Start writer goroutine
	go s.writer()

	// Start ping goroutine
	go s.pinger()

	// Read from WebSocket and send to UDP client
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_, framedData, err := conn.ReadMessage()
		if err != nil {
			if s.ctx.Err() == nil && err != io.EOF {
				s.logger.Printf("udptlspipe: WebSocket read error: %v", err)
			}
			return
		}

		// Unpack the message to extract the original UDP data
		data, err := unpackMessage(framedData)
		if err != nil {
			s.logger.Printf("udptlspipe: Failed to unpack message: %v", err)
			continue
		}

		_, err = s.udpConn.WriteToUDP(data, s.clientAddr)
		if err != nil {
			s.logger.Printf("udptlspipe: UDP write error: %v", err)
		}
	}
}

// dialTLSWithFingerprint creates a TLS connection with the specified fingerprint profile
func dialTLSWithFingerprint(ctx context.Context, network, addr, serverName string, secure bool, clientHelloID tls.ClientHelloID, logger Logger) (net.Conn, error) {
	// Create a TCP connection first
	dialer := &net.Dialer{
		Timeout: dialTimeout,
	}

	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	// Create utls config
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !secure,
	}

	// Create utls client with the specified fingerprint
	tlsConn := tls.UClient(tcpConn, tlsConfig, clientHelloID)

	// Perform the TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	logger.Printf("udptlspipe: TLS handshake completed with fingerprint %s", clientHelloID.Str())

	return tlsConn, nil
}

func (s *clientSession) writer() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case data := <-s.sendCh:
			s.wsMu.Lock()
			if s.wsConn != nil {
				// Pack the message with length-prefix framing before sending
				framedData := packMessage(data)
				s.wsConn.SetWriteDeadline(time.Now().Add(writeTimeout))
				err := s.wsConn.WriteMessage(websocket.BinaryMessage, framedData)
				if err != nil {
					s.logger.Printf("udptlspipe: WebSocket write error: %v", err)
				}
			}
			s.wsMu.Unlock()
		}
	}
}

func (s *clientSession) pinger() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.wsMu.Lock()
			if s.wsConn != nil {
				s.wsConn.SetWriteDeadline(time.Now().Add(writeTimeout))
				err := s.wsConn.WriteMessage(websocket.PingMessage, nil)
				if err != nil {
					s.logger.Printf("udptlspipe: Ping error: %v", err)
				}
			}
			s.wsMu.Unlock()
		}
	}
}

func (s *clientSession) send(data []byte) {
	select {
	case s.sendCh <- data:
	default:
		// Channel full, drop packet
		s.logger.Printf("udptlspipe: Send channel full, dropping packet")
	}
}

func (s *clientSession) isAlive() bool {
	s.aliveMu.RLock()
	defer s.aliveMu.RUnlock()
	return s.alive
}

func (s *clientSession) close() {
	s.cancel()
	s.wsMu.Lock()
	if s.wsConn != nil {
		s.wsConn.Close()
	}
	s.wsMu.Unlock()
}
