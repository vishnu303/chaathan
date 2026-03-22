package database

import (
	"strings"
	"time"
)

// HostMetadata stores lightweight per-host signals used by ROI ranking.
type HostMetadata struct {
	ScanID          int64     `json:"scan_id"`
	Host            string    `json:"host"`
	BaseURL         string    `json:"base_url,omitempty"`
	HeadersJSON     string    `json:"headers_json,omitempty"`
	HasCSP          bool      `json:"has_csp"`
	HasCacheHeaders bool      `json:"has_cache_headers"`
	LoginSurface    bool      `json:"login_surface"`
	ResponseBytes   int       `json:"response_bytes"`
	SSLExpired      bool      `json:"ssl_expired"`
	SSLSelfSigned   bool      `json:"ssl_self_signed"`
	SSLMismatch     bool      `json:"ssl_mismatch"`
	WeakTLS         bool      `json:"weak_tls"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// URLMetadata stores selected path-level signals used by ROI ranking.
type URLMetadata struct {
	ScanID          int64     `json:"scan_id"`
	URL             string    `json:"url"`
	Host            string    `json:"host"`
	HeadersJSON     string    `json:"headers_json,omitempty"`
	HasCSP          bool      `json:"has_csp"`
	HasCacheHeaders bool      `json:"has_cache_headers"`
	LoginSurface    bool      `json:"login_surface"`
	ResponseBytes   int       `json:"response_bytes"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func UpsertHostMetadata(scanID int64, meta HostMetadata) error {
	meta.Host = strings.ToLower(strings.TrimSpace(meta.Host))
	_, err := DB.Exec(
		`INSERT INTO host_metadata (
			scan_id, host, base_url, headers_json, has_csp, has_cache_headers,
			login_surface, response_bytes, ssl_expired, ssl_self_signed,
			ssl_mismatch, weak_tls
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, host) DO UPDATE SET
			base_url = CASE
				WHEN excluded.base_url != '' THEN excluded.base_url
				ELSE host_metadata.base_url
			END,
			headers_json = CASE
				WHEN excluded.headers_json != '' THEN excluded.headers_json
				ELSE host_metadata.headers_json
			END,
			has_csp = host_metadata.has_csp OR excluded.has_csp,
			has_cache_headers = host_metadata.has_cache_headers OR excluded.has_cache_headers,
			login_surface = host_metadata.login_surface OR excluded.login_surface,
			response_bytes = CASE
				WHEN excluded.response_bytes > host_metadata.response_bytes THEN excluded.response_bytes
				ELSE host_metadata.response_bytes
			END,
			ssl_expired = host_metadata.ssl_expired OR excluded.ssl_expired,
			ssl_self_signed = host_metadata.ssl_self_signed OR excluded.ssl_self_signed,
			ssl_mismatch = host_metadata.ssl_mismatch OR excluded.ssl_mismatch,
			weak_tls = host_metadata.weak_tls OR excluded.weak_tls,
			updated_at = CURRENT_TIMESTAMP`,
		scanID,
		meta.Host,
		meta.BaseURL,
		meta.HeadersJSON,
		meta.HasCSP,
		meta.HasCacheHeaders,
		meta.LoginSurface,
		meta.ResponseBytes,
		meta.SSLExpired,
		meta.SSLSelfSigned,
		meta.SSLMismatch,
		meta.WeakTLS,
	)
	return err
}

func UpsertURLMetadata(scanID int64, meta URLMetadata) error {
	meta.URL = strings.TrimSpace(meta.URL)
	meta.Host = strings.ToLower(strings.TrimSpace(meta.Host))
	_, err := DB.Exec(
		`INSERT INTO url_metadata (
			scan_id, url, host, headers_json, has_csp, has_cache_headers,
			login_surface, response_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, url) DO UPDATE SET
			host = CASE
				WHEN excluded.host != '' THEN excluded.host
				ELSE url_metadata.host
			END,
			headers_json = CASE
				WHEN excluded.headers_json != '' THEN excluded.headers_json
				ELSE url_metadata.headers_json
			END,
			has_csp = excluded.has_csp,
			has_cache_headers = excluded.has_cache_headers,
			login_surface = excluded.login_surface,
			response_bytes = CASE
				WHEN excluded.response_bytes > url_metadata.response_bytes THEN excluded.response_bytes
				ELSE url_metadata.response_bytes
			END,
			updated_at = CURRENT_TIMESTAMP`,
		scanID,
		meta.URL,
		meta.Host,
		meta.HeadersJSON,
		meta.HasCSP,
		meta.HasCacheHeaders,
		meta.LoginSurface,
		meta.ResponseBytes,
	)
	return err
}

func GetHostMetadata(scanID int64) ([]HostMetadata, error) {
	rows, err := DB.Query(
		`SELECT scan_id, host, base_url, headers_json, has_csp, has_cache_headers,
		        login_surface, response_bytes, ssl_expired, ssl_self_signed,
		        ssl_mismatch, weak_tls, created_at, updated_at
		 FROM host_metadata WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metas []HostMetadata
	for rows.Next() {
		var meta HostMetadata
		if err := rows.Scan(
			&meta.ScanID,
			&meta.Host,
			&meta.BaseURL,
			&meta.HeadersJSON,
			&meta.HasCSP,
			&meta.HasCacheHeaders,
			&meta.LoginSurface,
			&meta.ResponseBytes,
			&meta.SSLExpired,
			&meta.SSLSelfSigned,
			&meta.SSLMismatch,
			&meta.WeakTLS,
			&meta.CreatedAt,
			&meta.UpdatedAt,
		); err != nil {
			return nil, err
		}
		metas = append(metas, meta)
	}

	return metas, nil
}

func GetURLMetadata(scanID int64) ([]URLMetadata, error) {
	rows, err := DB.Query(
		`SELECT scan_id, url, host, headers_json, has_csp, has_cache_headers,
		        login_surface, response_bytes, created_at, updated_at
		 FROM url_metadata WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metas []URLMetadata
	for rows.Next() {
		var meta URLMetadata
		if err := rows.Scan(
			&meta.ScanID,
			&meta.URL,
			&meta.Host,
			&meta.HeadersJSON,
			&meta.HasCSP,
			&meta.HasCacheHeaders,
			&meta.LoginSurface,
			&meta.ResponseBytes,
			&meta.CreatedAt,
			&meta.UpdatedAt,
		); err != nil {
			return nil, err
		}
		metas = append(metas, meta)
	}

	return metas, nil
}
