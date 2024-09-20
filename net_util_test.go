package xdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupMacAddress(t *testing.T) {
	iface, localIP, err := GetInterfaceForIP("8.8.8.8")
	assert.NoError(t, err)
	assert.NotEmpty(t, iface)
	assert.NotEmpty(t, localIP)

	mac, err := LookupMacAddress(localIP)
	assert.NoError(t, err)
	assert.NotEmpty(t, mac)
	t.Log(mac)

	gwTP, err := getGatewayIP()
	assert.NoError(t, err)

	mac, err = LookupMacAddress(gwTP.String())
	assert.NoError(t, err)
	assert.NotEmpty(t, mac)
	t.Log(mac)

	mac, err = LookupMacAddress("8.8.8.8")
	assert.NoError(t, err)
	assert.NotEmpty(t, mac)
	t.Log(mac)
}

func TestGetInterfaceForIP(t *testing.T) {
	iface, localIP, err := GetInterfaceForIP("127.0.0.1")
	assert.NoError(t, err)
	assert.NotEmpty(t, iface)
	assert.NotEmpty(t, localIP)
}
