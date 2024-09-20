package xdp

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/smallnest/xdp/syncx"
)

var (
	ErrPacketIPMismatch = errors.New("packet and destination IP length mismatch")
)

// XDPIPConn is a IPv4 connection that uses XDP to send and receive IP packets in batch.
type XDPIPv4Conn struct {
	iface  *net.Interface
	srcIP  string
	srcMAC net.HardwareAddr

	dstMacs *syncx.Map[string, net.HardwareAddr]

	sock *Socket
}

// NewXDPIPv4Conn creates a new XDPIPv4Conn.
func NewXDPIPv4Conn(localIP string, QueueID int, options *SocketOptions) (*XDPIPv4Conn, error) {
	iface, _, err := GetInterfaceForIP(localIP)
	if err != nil {
		return nil, err
	}

	sock, err := NewSocket(iface.Index, QueueID, options)
	if err != nil {
		return nil, err
	}

	conn := &XDPIPv4Conn{
		iface:   iface,
		srcIP:   localIP,
		srcMAC:  iface.HardwareAddr,
		dstMacs: &syncx.Map[string, net.HardwareAddr]{},

		sock: sock,
	}
	return conn, nil
}

// Socket returns the underlying socket.
func (c *XDPIPv4Conn) Socket() *Socket {
	return c.sock
}

// WriteTo writes IP packets to the given destination IP.
// pkts is a slice of eth packets.
// dstIP is the destination IP address.
// It returns the count of packets written and an error, if any.
// You **must**  the rest of the packets in the slice. Drop them or resend up to you.
func (c *XDPIPv4Conn) WriteTo(pkts [][]byte, dstIP string) (int, error) {
	n := len(pkts)
	descs := c.sock.GetDescs(n, false) // Get n tx descriptors from the socket.
	for i := range descs {
		frameLen := copy(c.sock.GetFrame(descs[i]), pkts[i])
		descs[i].Len = uint32(frameLen)
	}

	_ = c.sock.Transmit(descs)

	_, completed, err := c.sock.Poll(-1)

	return completed, err
}

// WriteToIP writes IP packets to the given destination IPs.
func (c *XDPIPv4Conn) WriteToIP(pkts [][]byte, dstIPs []string) (int, error) {
	if len(pkts) != len(dstIPs) {
		return 0, ErrPacketIPMismatch
	}

	n := len(pkts)
	descs := c.sock.GetDescs(n, false) // Get n tx descriptors from the socket.
	for i := range descs {
		dstMAC, ok := c.dstMacs.Load(dstIPs[i])
		if !ok {
			mac, err := LookupMacAddress(dstIPs[i])
			if err != nil {
				return 0, err
			}
			dstMAC = mac
			c.dstMacs.Store(dstIPs[i], dstMAC)
		}

		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr(c.srcMAC),
			DstMAC:       net.HardwareAddr(dstMAC),
			EthernetType: layers.EthernetTypeIPv4,
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err := gopacket.SerializeLayers(buf, opts, eth, gopacket.Payload(pkts[i]))
		if err != nil {
			return 0, err
		}

		frameLen := copy(c.sock.GetFrame(descs[i]), buf.Bytes())
		descs[i].Len = uint32(frameLen)
	}

	_ = c.sock.Transmit(descs)

	_, completed, err := c.sock.Poll(-1)

	return completed, err
}

// BuildIPPacket builds an IP packet with the given parameters and UDP protocol.
func (c *XDPIPv4Conn) BuildIPPacket(srcIP, dstIP string, srcPort, dstPort int, ttl, tos int, payload []byte) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()

	srcMAC, ok := c.dstMacs.Load(srcIP)
	if !ok {
		mac, err := LookupMacAddress(srcIP)
		if err != nil {
			return nil, err
		}
		srcMAC = mac
		c.dstMacs.Store(srcIP, srcMAC)
	}

	dstMAC, ok := c.dstMacs.Load(dstIP)
	if !ok {
		mac, err := LookupMacAddress(dstIP)
		if err != nil {
			return nil, err
		}
		fmt.Println("@@@@@", dstIP, mac.String())
		dstMAC = mac
		c.dstMacs.Store(dstIP, dstMAC)
	}

	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC),
		DstMAC:       net.HardwareAddr(dstMAC),
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      uint8(ttl),
		TOS:      uint8(tos),
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer) // Important for checksum calculation

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, options, ethLayer, ipLayer, udpLayer, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	return buf.Bytes(), nil
}

// Close closes the connection.
func (c *XDPIPv4Conn) Close() error {
	return c.sock.Close()
}
