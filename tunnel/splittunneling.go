/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 WireGate. All Rights Reserved.
 */

package tunnel

import (
	"fmt"
	"log"
	"net"

	"golang.org/x/sys/windows"

	"github.com/NOXCIS/wiregate-windows/conf"
	"github.com/NOXCIS/wiregate-windows/tunnel/winipcfg"
)

// SplitTunnelingManager handles split tunneling route configuration
type SplitTunnelingManager struct {
	luid              winipcfg.LUID
	config            *conf.SplitTunnelingConfig
	addedRoutes       []net.IPNet
	resolvedSites     map[string][]net.IP
	originalMetricV4  uint32
	originalMetricV6  uint32
	originalAutoMetricV4 bool
	originalAutoMetricV6 bool
	metricModified    bool
}

// NewSplitTunnelingManager creates a new split tunneling manager
func NewSplitTunnelingManager(luid winipcfg.LUID, config *conf.SplitTunnelingConfig) *SplitTunnelingManager {
	return &SplitTunnelingManager{
		luid:          luid,
		config:        config,
		addedRoutes:   make([]net.IPNet, 0),
		resolvedSites: make(map[string][]net.IP),
	}
}

// Apply applies the split tunneling configuration
func (m *SplitTunnelingManager) Apply() error {
	if m.config == nil || m.config.Mode == conf.SplitModeAllSites {
		log.Println("Split tunneling: Mode is AllSites, no routes to configure")
		return nil
	}

	log.Printf("Split tunneling: Applying mode %d with %d sites", m.config.Mode, len(m.config.Sites))

	// Resolve all sites to IP addresses
	for _, site := range m.config.Sites {
		ips, err := m.resolveSite(site)
		if err != nil {
			log.Printf("Split tunneling: Failed to resolve site %s: %v", site, err)
			continue
		}
		m.resolvedSites[site] = ips
		log.Printf("Split tunneling: Resolved %s to %v", site, ips)
	}

	switch m.config.Mode {
	case conf.SplitModeAllExceptSites:
		return m.applyExcludeRoutes()
	case conf.SplitModeOnlyForwardSites:
		return m.applyIncludeRoutes()
	}

	return nil
}

// Remove removes all split tunneling routes and restores original interface metrics
func (m *SplitTunnelingManager) Remove() error {
	log.Printf("Split tunneling: Removing %d routes", len(m.addedRoutes))

	for _, route := range m.addedRoutes {
		if err := m.removeRoute(route); err != nil {
			log.Printf("Split tunneling: Failed to remove route %s: %v", route.String(), err)
		}
	}

	m.addedRoutes = make([]net.IPNet, 0)
	
	// Restore original interface metrics if they were modified
	if m.metricModified {
		// Restore IPv4 metric
		ipif, err := m.luid.IPInterface(windows.AF_INET)
		if err == nil {
			ipif.UseAutomaticMetric = m.originalAutoMetricV4
			ipif.Metric = m.originalMetricV4
			if err := ipif.Set(); err != nil {
				log.Printf("Split tunneling: Failed to restore IPv4 interface metric: %v", err)
			} else {
				log.Printf("Split tunneling: Restored tunnel IPv4 interface metric to %d (auto=%v)", m.originalMetricV4, m.originalAutoMetricV4)
			}
		}
		
		// Restore IPv6 metric
		ipif6, err := m.luid.IPInterface(windows.AF_INET6)
		if err == nil {
			ipif6.UseAutomaticMetric = m.originalAutoMetricV6
			ipif6.Metric = m.originalMetricV6
			if err := ipif6.Set(); err != nil {
				log.Printf("Split tunneling: Failed to restore IPv6 interface metric: %v", err)
			} else {
				log.Printf("Split tunneling: Restored tunnel IPv6 interface metric to %d (auto=%v)", m.originalMetricV6, m.originalAutoMetricV6)
			}
		}
		
		m.metricModified = false
	}
	
	return nil
}

// resolveSite resolves a site (IP, CIDR, or domain) to IP addresses
func (m *SplitTunnelingManager) resolveSite(site string) ([]net.IP, error) {
	// First try to parse as CIDR prefix
	if _, ipnet, err := net.ParseCIDR(site); err == nil {
		return []net.IP{ipnet.IP}, nil
	}

	// Try to parse as plain IP address
	if ip := net.ParseIP(site); ip != nil {
		return []net.IP{ip}, nil
	}

	// Resolve as domain name
	ips, err := net.LookupIP(site)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no valid addresses found")
	}

	return ips, nil
}

// applyExcludeRoutes adds routes that bypass the VPN for specified sites
func (m *SplitTunnelingManager) applyExcludeRoutes() error {
	log.Println("Split tunneling: Applying exclude routes (AllExceptSites mode)")

	// Get the default gateway for the main interface
	defaultGateway, defaultLUID, err := m.getDefaultGateway()
	if err != nil {
		log.Printf("Split tunneling: Could not get default gateway: %v", err)
		return err
	}

	log.Printf("Split tunneling: Using default gateway %s", defaultGateway.String())

	for site, ips := range m.resolvedSites {
		for _, ip := range ips {
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}

			ipnet := net.IPNet{IP: ip, Mask: mask}

			// For exclude mode, we add a route through the default gateway on the physical interface
			if err := defaultLUID.AddRoute(ipnet, defaultGateway, 0); err != nil {
				log.Printf("Split tunneling: Failed to add exclude route for %s (%s): %v", site, ipnet.String(), err)
				continue
			}

			m.addedRoutes = append(m.addedRoutes, ipnet)
			log.Printf("Split tunneling: Added exclude route for %s via default gateway", ipnet.String())
		}
	}

	return nil
}

// applyIncludeRoutes sets up routing so only specified sites go through VPN
func (m *SplitTunnelingManager) applyIncludeRoutes() error {
	log.Println("Split tunneling: Applying include routes (OnlyForwardSites mode)")

	// Add routes for specified sites through the tunnel interface
	// These are more specific routes, so they'll take precedence over the default route
	for site, ips := range m.resolvedSites {
		for _, ip := range ips {
			var mask net.IPMask
			var nextHop net.IP
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
				nextHop = net.IPv4zero
			} else {
				mask = net.CIDRMask(128, 128)
				nextHop = net.IPv6zero
			}

			ipnet := net.IPNet{IP: ip, Mask: mask}

			// Add route through the tunnel interface (no next hop needed for on-link)
			if err := m.luid.AddRoute(ipnet, nextHop, 0); err != nil {
				log.Printf("Split tunneling: Failed to add include route for %s (%s): %v", site, ipnet.String(), err)
				continue
			}

			m.addedRoutes = append(m.addedRoutes, ipnet)
			log.Printf("Split tunneling: Added include route for %s via tunnel", ipnet.String())
		}
	}

	// For OnlyForwardSites mode, we need to ensure non-specified traffic bypasses the tunnel
	// The tunnel has a default route (0.0.0.0/0) with metric 0
	// We modify the tunnel interface metric to be HIGHER (1) so the physical interface's
	// default route (metric 0) will be preferred for non-specified traffic
	// More specific routes (the specified sites) will still match and go through tunnel
	// because more specific routes take precedence regardless of metric
	
	// Modify tunnel interface metric for IPv4 to prefer physical interface's default route
	ipif, err := m.luid.IPInterface(windows.AF_INET)
	if err == nil {
		m.originalMetricV4 = ipif.Metric
		m.originalAutoMetricV4 = ipif.UseAutomaticMetric
		ipif.UseAutomaticMetric = false
		ipif.Metric = 1 // Higher than physical interface (typically 0)
		if err := ipif.Set(); err != nil {
			log.Printf("Split tunneling: Failed to set IPv4 interface metric: %v", err)
		} else {
			m.metricModified = true
			log.Printf("Split tunneling: Set tunnel IPv4 interface metric to 1 (was %d, auto=%v) to prefer physical interface default route", m.originalMetricV4, m.originalAutoMetricV4)
		}
	}
	
	// Modify tunnel interface metric for IPv6 to prefer physical interface's default route
	ipif6, err := m.luid.IPInterface(windows.AF_INET6)
	if err == nil {
		m.originalMetricV6 = ipif6.Metric
		m.originalAutoMetricV6 = ipif6.UseAutomaticMetric
		ipif6.UseAutomaticMetric = false
		ipif6.Metric = 1 // Higher than physical interface (typically 0)
		if err := ipif6.Set(); err != nil {
			log.Printf("Split tunneling: Failed to set IPv6 interface metric: %v", err)
		} else {
			m.metricModified = true
			log.Printf("Split tunneling: Set tunnel IPv6 interface metric to 1 (was %d, auto=%v) to prefer physical interface default route", m.originalMetricV6, m.originalAutoMetricV6)
		}
	}

	return nil
}

// getDefaultGateway finds the default gateway for non-VPN traffic
func (m *SplitTunnelingManager) getDefaultGateway() (net.IP, winipcfg.LUID, error) {
	// Get all IPv4 routes
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get routing table: %w", err)
	}

	for _, route := range routes {
		// Look for default route (0.0.0.0/0) that's not on our tunnel interface
		if route.DestinationPrefix.PrefixLength == 0 && route.InterfaceLUID != m.luid {
			nextHop := route.NextHop.IP()
			if nextHop != nil && !nextHop.IsUnspecified() {
				return nextHop, route.InterfaceLUID, nil
			}
		}
	}

	return nil, 0, fmt.Errorf("no default gateway found")
}

// removeRoute removes a previously added route
func (m *SplitTunnelingManager) removeRoute(ipnet net.IPNet) error {
	// Try to delete from tunnel interface first
	err := m.luid.DeleteRoute(ipnet, net.IPv4zero)
	if err == nil {
		return nil
	}

	// If that fails, try to find it in other interfaces
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return err
	}

	for _, route := range routes {
		routeNet := route.DestinationPrefix.IPNet()
		if routeNet.IP.Equal(ipnet.IP) {
			ones1, bits1 := routeNet.Mask.Size()
			ones2, bits2 := ipnet.Mask.Size()
			if ones1 == ones2 && bits1 == bits2 {
				return route.Delete()
			}
		}
	}

	return nil
}
