package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session tracks an MCP client session.
type Session struct {
	ID        string
	ClientInfo map[string]interface{} // From initialize clientInfo
	Created   time.Time
	LastSeen  time.Time
	Requests  int
	ToolCalls map[string]int // tool name -> call count
}

// SessionStore manages MCP sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewSessionStore creates a new session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// Create creates a new session and returns its ID.
func (s *SessionStore) Create(clientInfo map[string]interface{}) string {
	id := generateSessionID()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = &Session{
		ID:         id,
		ClientInfo: clientInfo,
		Created:    time.Now(),
		LastSeen:   time.Now(),
		ToolCalls:  make(map[string]int),
	}
	return id
}

// Get retrieves a session by ID, updating LastSeen.
func (s *SessionStore) Get(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	sess.LastSeen = time.Now()
	sess.Requests++
	return sess
}

// RecordToolCall records a tool invocation.
func (s *SessionStore) RecordToolCall(sessionID, toolName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[sessionID]; ok {
		sess.ToolCalls[toolName]++
	}
}

// All returns a snapshot of all sessions.
func (s *SessionStore) All() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		result = append(result, sess)
	}
	return result
}

// Delete removes a session.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
