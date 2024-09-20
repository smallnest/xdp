/*
sendudp pre-generates a frame with a UDP packet with a payload of the given
size and starts sending it in and endless loop to given destination as fast as
possible.
*/
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	xdp "github.com/smallnest/xdp"
)

// ...
var (
	QueueID     int
	SrcIP       string
	DstIP       string
	SrcPort     uint
	DstPort     uint
	PayloadSize uint
	Batch       int
)

func main() {
	flag.IntVar(&QueueID, "queue", 0, "The queue on the network interface to attach to.")
	flag.StringVar(&SrcIP, "srcip", "192.168.1.11", "Source IP address to use in sent frames.")
	flag.StringVar(&DstIP, "dstip", "192.168.3.15", "Destination IP address to use in sent frames.")
	flag.UintVar(&SrcPort, "srcport", 12345, "Source UDP port.")
	flag.UintVar(&DstPort, "dstport", 54321, "Destination UDP port.")
	flag.UintVar(&PayloadSize, "payloadsize", 1400, "Size of the UDP payload.")
	flag.IntVar(&Batch, "batch", 10, "Size of packets to send in a batch.")

	flag.Parse()

	conn, err := xdp.NewXDPIPv4Conn(SrcIP, QueueID, nil, nil)
	if err != nil {
		panic(err)
	}

	var frameLen int
	{
		data, _ := conn.BuildIPPacket(SrcIP, DstIP, int(SrcPort), int(DstPort), 64, 0, make([]byte, PayloadSize))
		frameLen = len(data)
	}

	fmt.Printf("sending UDP packets from %v  to %v ...\n", SrcIP, DstIP)

	// calc send stat
	go func() {
		var err error
		var prev xdp.Stats
		var cur xdp.Stats
		var numPkts uint64
		xsk := conn.Socket()

		for i := uint64(0); ; i++ {
			time.Sleep(time.Duration(1) * time.Second)
			cur, err = xsk.Stats()
			if err != nil {
				panic(err)
			}
			numPkts = cur.Completed - prev.Completed
			fmt.Printf("%d packets/s (%d Mb/s)\n", numPkts, (numPkts*uint64(frameLen)*8)/(1000*1000))
			prev = cur
		}
	}()

	go func() {
		index := 0
		data := make([][]byte, Batch)
		for {
			for i := 0; i < Batch; i++ {
				index++
				payload := make([]byte, PayloadSize)
				flag := fmt.Sprintf("packet id: %d, time:%d\n", index, time.Now().UnixNano())
				copy(payload, flag)
				data[i], _ = conn.BuildIPPacket(SrcIP, DstIP, int(SrcPort), int(DstPort), 64, 0, payload)
			}

			n, err := conn.Send(data, DstIP)
			if err != nil {
				panic(err)
			}
			fmt.Printf("sent %d packets\n", n)

			time.Sleep(time.Second)
		}

	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	conn.Close()
}
