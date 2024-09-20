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
	queueID int
	// for sender
	iface   *net.Interface
	srcIP   string
	srcMAC  net.HardwareAddr
	dstMacs *syncx.Map[string, net.HardwareAddr]

	// for receiver
	prog *Program

	sock *Socket
}

// NewXDPIPv4Conn creates a new XDPIPv4Conn.
func NewXDPIPv4Conn(localIP string, queueID int, options *SocketOptions, prog *Program) (*XDPIPv4Conn, error) {
	iface, _, err := GetInterfaceForIP(localIP)
	if err != nil {
		return nil, err
	}

	sock, err := NewSocket(iface.Index, queueID, options)
	if err != nil {
		return nil, err
	}

	if prog != nil {
		if err := prog.Attach(iface.Index); err != nil {
			sock.Close()
			return nil, fmt.Errorf("failed to attach XDP program: %w", err)
		}

		fmt.Println("attached")

		if err := prog.Register(queueID, sock.FD()); err != nil {
			prog.Detach(iface.Index)
			sock.Close()
			return nil, fmt.Errorf("failed to register XDP program: %w", err)
		}

		fmt.Println("registered")
	}

	conn := &XDPIPv4Conn{
		queueID: queueID,

		iface:   iface,
		srcIP:   localIP,
		srcMAC:  iface.HardwareAddr,
		dstMacs: &syncx.Map[string, net.HardwareAddr]{},

		prog: prog,

		sock: sock,
	}
	return conn, nil
}

// Socket returns the underlying socket.
func (c *XDPIPv4Conn) Socket() *Socket {
	return c.sock
}

// Send sends IP packets to the given destination IP.
// pkts is a slice of eth packets.
// dstIP is the destination IP address.
// It returns the count of packets written and an error, if any.
// You **must**  the rest of the packets in the slice. Drop them or resend up to you.
func (c *XDPIPv4Conn) Send(pkts [][]byte, dstIP string) (int, error) {
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

// SendTo sends IP packets to the given destination IPs.
func (c *XDPIPv4Conn) SendTo(pkts [][]byte, dstIPs []string) (int, error) {
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

// ReadFrom reads IP packets from the connection.
// You **must** copy the packets to another buffer if you want to handle it in other goroutines.
func (c *XDPIPv4Conn) ReadFrom() (pkts [][]byte, err error) {
	if c.prog == nil {
		return nil, errors.New("no program set")
	}

	xsk := c.sock
	if n := xsk.NumFreeFillSlots(); n > 0 {
		xsk.Fill(xsk.GetDescs(n, true)) // Fill the free slots with Rx descriptors.
	}

	// Wait for receive - meaning the kernel has
	// produced one or more descriptors filled with a received
	// frame onto the Rx ring queue.
	numRx, _, err := xsk.Poll(-1)
	if err != nil {
		return nil, err
	}

	if numRx > 0 {
		rxDescs := xsk.Receive(numRx)

		for i := 0; i < len(rxDescs); i++ {
			pktData := xsk.GetFrame(rxDescs[i])
			pkts = append(pkts, pktData)
		}
	}

	return pkts, nil
}

// Close closes the connection.
func (c *XDPIPv4Conn) Close() error {
	if c.sock != nil {
		c.sock.Close()
	}
	if c.prog != nil {
		c.prog.Unregister(c.queueID)
		c.prog.Detach(c.iface.Index)
		c.prog.Close()
	}

	return nil
}
