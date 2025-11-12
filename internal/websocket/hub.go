package websocket

import (
	"encoding/json"
	"netsecanalyzer/pkg/logger"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Hub WebSocket 连接管理中心
type Hub struct {
	// 已注册的客户端
	clients map[*Client]bool

	// 客户端订阅的会话
	sessionClients map[uint]map[*Client]bool

	// 注册请求
	register chan *Client

	// 注销请求
	unregister chan *Client

	// 广播消息
	broadcast chan *Message

	// 会话消息
	sessionBroadcast chan *SessionMessage

	mu sync.RWMutex
}

// Client WebSocket 客户端
type Client struct {
	hub *Hub

	// WebSocket 连接
	conn *websocket.Conn

	// 发送消息的通道
	send chan []byte

	// 订阅的会话ID列表
	sessions map[uint]bool

	mu sync.RWMutex
}

// Message 广播消息
type Message struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
	Time time.Time   `json:"time"`
}

// SessionMessage 会话消息
type SessionMessage struct {
	SessionID uint
	Message   *Message
}

// NewHub 创建 Hub
func NewHub() *Hub {
	return &Hub{
		clients:          make(map[*Client]bool),
		sessionClients:   make(map[uint]map[*Client]bool),
		register:         make(chan *Client),
		unregister:       make(chan *Client),
		broadcast:        make(chan *Message, 256),
		sessionBroadcast: make(chan *SessionMessage, 256),
	}
}

// Run 运行 Hub
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			logger.GetLogger().Infof("WebSocket client registered, total: %d", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)

				// 从所有会话订阅中移除
				for sessionID := range client.sessions {
					if clients, ok := h.sessionClients[sessionID]; ok {
						delete(clients, client)
						if len(clients) == 0 {
							delete(h.sessionClients, sessionID)
						}
					}
				}
			}
			h.mu.Unlock()
			logger.GetLogger().Infof("WebSocket client unregistered, total: %d", len(h.clients))

		case message := <-h.broadcast:
			h.mu.RLock()
			data, err := json.Marshal(message)
			if err != nil {
				logger.GetLogger().Errorf("Failed to marshal broadcast message: %v", err)
				h.mu.RUnlock()
				continue
			}

			for client := range h.clients {
				select {
				case client.send <- data:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()

		case sessionMsg := <-h.sessionBroadcast:
			h.mu.RLock()
			clients, ok := h.sessionClients[sessionMsg.SessionID]
			if !ok {
				h.mu.RUnlock()
				continue
			}

			data, err := json.Marshal(sessionMsg.Message)
			if err != nil {
				logger.GetLogger().Errorf("Failed to marshal session message: %v", err)
				h.mu.RUnlock()
				continue
			}

			for client := range clients {
				select {
				case client.send <- data:
				default:
					close(client.send)
					delete(h.clients, client)
					delete(clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast 广播消息到所有客户端
func (h *Hub) Broadcast(msgType string, data interface{}) {
	message := &Message{
		Type: msgType,
		Data: data,
		Time: time.Now(),
	}

	select {
	case h.broadcast <- message:
	default:
		logger.GetLogger().Warn("Broadcast channel full, dropping message")
	}
}

// BroadcastToSession 广播消息到指定会话的订阅者
func (h *Hub) BroadcastToSession(sessionID uint, msgType string, data interface{}) {
	message := &Message{
		Type: msgType,
		Data: data,
		Time: time.Now(),
	}

	sessionMsg := &SessionMessage{
		SessionID: sessionID,
		Message:   message,
	}

	select {
	case h.sessionBroadcast <- sessionMsg:
	default:
		logger.GetLogger().Warn("Session broadcast channel full, dropping message")
	}
}

// SubscribeSession 订阅会话
func (h *Hub) SubscribeSession(client *Client, sessionID uint) {
	h.mu.Lock()
	defer h.mu.Unlock()

	client.mu.Lock()
	client.sessions[sessionID] = true
	client.mu.Unlock()

	if _, ok := h.sessionClients[sessionID]; !ok {
		h.sessionClients[sessionID] = make(map[*Client]bool)
	}
	h.sessionClients[sessionID][client] = true

	logger.GetLogger().Infof("Client subscribed to session %d", sessionID)
}

// UnsubscribeSession 取消订阅会话
func (h *Hub) UnsubscribeSession(client *Client, sessionID uint) {
	h.mu.Lock()
	defer h.mu.Unlock()

	client.mu.Lock()
	delete(client.sessions, sessionID)
	client.mu.Unlock()

	if clients, ok := h.sessionClients[sessionID]; ok {
		delete(clients, client)
		if len(clients) == 0 {
			delete(h.sessionClients, sessionID)
		}
	}

	logger.GetLogger().Infof("Client unsubscribed from session %d", sessionID)
}

// GetClientCount 获取客户端数量
func (h *Hub) GetClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// GetSessionSubscribers 获取会话订阅者数量
func (h *Hub) GetSessionSubscribers(sessionID uint) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if clients, ok := h.sessionClients[sessionID]; ok {
		return len(clients)
	}
	return 0
}

// RegisterClient 注册客户端
func (h *Hub) RegisterClient(client *Client) {
	h.register <- client
}

// UnregisterClient 注销客户端
func (h *Hub) UnregisterClient(client *Client) {
	h.unregister <- client
}
