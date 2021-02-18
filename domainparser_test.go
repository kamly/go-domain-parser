package domainparser

import (
	"github.com/likexian/gokit/assert"
	"testing"
)

func TestAsk(t *testing.T) {
	tests := []string{
		"charmingkamly.cn",
	}

	for _, v := range tests {
		ips, err := Resolve(v, "119.29.29.29")
		assert.Nil(t, err)
		assert.Equal(t, ips[0].String(), "139.199.179.114")
	}
}
