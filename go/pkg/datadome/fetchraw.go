package datadome

import (
	"context"
	"io"
	"net/http"
)

func (c *Client) FetchRaw(ctx context.Context, method, targetURL string, headers map[string]string) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	setChromeHeaders(req)
	req.Header.Set("user-agent", defaultUA)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &FetchResult{Status: resp.StatusCode, Headers: resp.Header, Body: body}, nil
}
