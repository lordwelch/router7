package dns

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

type dohClient struct {
	dns.Client
	http http.Client
}

func (d *dohClient) Exchange(m *dns.Msg, address string) (r *dns.Msg, rtt time.Duration, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	n := m.Copy()
	n.Id = 0
	body, err := n.Pack()
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "router7/dnsd")
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, 0, err
	}
	r = new(dns.Msg)
	err = r.Unpack(b)
	if err != nil {
		return nil, 0, err
	}
	r.Id = m.Id
	return r, 0, nil
}
