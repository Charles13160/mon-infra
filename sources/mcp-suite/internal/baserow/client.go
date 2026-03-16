package baserow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

type LinkedField struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

type BaserowRow struct {
	ID          int            `json:"id"`
	Licences    string         `json:"licences"`
	DateLimite  string         `json:"date_limite"`
	Active      bool           `json:"Active"`
	UUID        string         `json:"UUID"`
	Clients     []LinkedField  `json:"CLIENTS"`
	MCPServices []LinkedField  `json:"MCP SERVICES"`
}

type BaserowCustomerRow struct {
	ID       int            `json:"id"`
	Clients  string         `json:"clients"` // Simple string field
	Services []LinkedField  `json:"SERVICES"` // Linked field
	Licences []LinkedField  `json:"LICENCES"` // Linked field
	Devis    []LinkedField  `json:"DEVIS"` // Linked field (was string, now array)
}

type ListRowsResponse struct {
	Count   int           `json:"count"`
	Results []BaserowRow  `json:"results"`
}

type ListCustomersResponse struct {
	Count   int                   `json:"count"`
	Results []BaserowCustomerRow  `json:"results"`
}

func (c *Client) ListLicenses(ctx context.Context, tableID int) ([]BaserowRow, error) {
	url := fmt.Sprintf("%s/api/database/rows/table/%d/?user_field_names=true", c.baseURL, tableID)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Token "+c.token)
	
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("baserow API error %d: %s", resp.StatusCode, string(body))
	}
	
	var result ListRowsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return result.Results, nil
}

func (c *Client) ListCustomers(ctx context.Context, tableID int) ([]BaserowCustomerRow, error) {
	url := fmt.Sprintf("%s/api/database/rows/table/%d/?user_field_names=true", c.baseURL, tableID)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Token "+c.token)
	
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("baserow API error %d: %s", resp.StatusCode, string(body))
	}
	
	var result ListCustomersResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return result.Results, nil
}
