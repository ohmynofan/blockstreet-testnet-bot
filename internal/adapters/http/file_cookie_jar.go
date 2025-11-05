package http

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"net/http"
	"net/url"
)

type fileCookieJar struct {
	mu      sync.Mutex
	path    string
	cookies map[string][]*http.Cookie
}

type storedCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Expires  time.Time `json:"expires"`
	Secure   bool      `json:"secure"`
	HttpOnly bool      `json:"httpOnly"`
}

func newFileCookieJar(path string) (*fileCookieJar, error) {
	jar := &fileCookieJar{
		path:    path,
		cookies: make(map[string][]*http.Cookie),
	}
	if err := jar.load(); err != nil {
		return nil, err
	}
	return jar, nil
}

func (j *fileCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if cookies == nil {
		return
	}

	for _, c := range cookies {
		key := domainKey(c.Domain, u.Host)
		list := j.cookies[key]
		updated := false
		for i, existing := range list {
			if strings.EqualFold(existing.Name, c.Name) && cookiePathMatch(existing.Path, c.Path) {
				if shouldDelete(c) {
					list = append(list[:i], list[i+1:]...)
				} else {
					list[i] = cloneCookie(c)
				}
				updated = true
				break
			}
		}
		if !updated && !shouldDelete(c) {
			list = append(list, cloneCookie(c))
		}
		j.cookies[key] = list
	}

	_ = j.save()
}

func (j *fileCookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()

	var result []*http.Cookie
	if u == nil {
		return result
	}

	host := canonicalHost(u.Host)
	now := time.Now()

	for domain, list := range j.cookies {
		filtered := list[:0]
		for _, c := range list {
			if isExpired(c, now) {
				continue
			}
			if !domainMatches(host, domain) {
				filtered = append(filtered, c)
				continue
			}
			if !cookiePathMatch(c.Path, u.Path) {
				filtered = append(filtered, c)
				continue
			}
			result = append(result, cloneCookie(c))
			filtered = append(filtered, c)
		}
		j.cookies[domain] = filtered
	}

	_ = j.save()
	return result
}

func (j *fileCookieJar) load() error {
	if j.path == "" {
		return nil
	}
	data, err := os.ReadFile(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var stored map[string][]storedCookie
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}

	for domain, list := range stored {
		for _, sc := range list {
			c := &http.Cookie{
				Name:     sc.Name,
				Value:    sc.Value,
				Domain:   sc.Domain,
				Path:     sc.Path,
				Expires:  sc.Expires,
				Secure:   sc.Secure,
				HttpOnly: sc.HttpOnly,
			}
			j.cookies[domain] = append(j.cookies[domain], c)
		}
	}
	return nil
}

func (j *fileCookieJar) save() error {
	if j.path == "" {
		return nil
	}

	stored := make(map[string][]storedCookie, len(j.cookies))
	for domain, list := range j.cookies {
		for _, c := range list {
			stored[domain] = append(stored[domain], storedCookie{
				Name:     c.Name,
				Value:    c.Value,
				Domain:   c.Domain,
				Path:     c.Path,
				Expires:  c.Expires,
				Secure:   c.Secure,
				HttpOnly: c.HttpOnly,
			})
		}
	}

	if err := os.MkdirAll(filepath.Dir(j.path), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(j.path, data, 0o600)
}

func cloneCookie(c *http.Cookie) *http.Cookie {
	clone := *c
	return &clone
}

func (j *fileCookieJar) HasCookies() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, list := range j.cookies {
		if len(list) > 0 {
			return true
		}
	}
	return false
}

func (j *fileCookieJar) Clear() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = make(map[string][]*http.Cookie)
	if j.path != "" {
		if err := os.Remove(j.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func canonicalHost(host string) string {
	host = strings.ToLower(host)
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

func domainKey(cookieDomain, host string) string {
	if cookieDomain != "" {
		return canonicalHost(strings.TrimPrefix(cookieDomain, "."))
	}
	return canonicalHost(host)
}

func domainMatches(host, domain string) bool {
	host = canonicalHost(host)
	domain = canonicalHost(domain)
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

func cookiePathMatch(cookiePath, reqPath string) bool {
	if cookiePath == "" {
		cookiePath = "/"
	}
	if !strings.HasPrefix(reqPath, cookiePath) {
		return false
	}
	return true
}

func shouldDelete(c *http.Cookie) bool {
	if c.MaxAge < 0 {
		return true
	}
	if !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
		return true
	}
	return false
}

func isExpired(c *http.Cookie, now time.Time) bool {
	if c.MaxAge < 0 {
		return true
	}
	if !c.Expires.IsZero() && c.Expires.Before(now) {
		return true
	}
	return false
}
