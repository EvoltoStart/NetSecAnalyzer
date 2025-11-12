package websocket

import (
	"encoding/json"
	"netsecanalyzer/pkg/logger"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// 写入等待时间
	writeWait = 10 * time.Second

	// Pong 等待时间
	pongWait = 60 * time.Second

	// Ping 周期（必须小于 pongWait）
	pingPeriod = (pongWait * 9) / 10

	// 最大消息大小
	maxMessageSize = 512
)

// ClientMessage 客户端消息
type ClientMessage struct {
	Type      string      `json:"type"`
	SessionID uint        `json:"session_id,omitempty"`
	Data      interface{} `json:"data,omitempty"`
}

// NewClient 创建客户端
func NewClient(hub *Hub, conn *websocket.Conn) *Client {
	return &Client{
		hub:      hub,
		conn:     conn,
		send:     make(chan []byte, 256),
		sessions: make(map[uint]bool),
	}
}

// ReadPump 从 WebSocket 连接读取消息
func (c *Client) ReadPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	c.conn.SetReadLimit(maxMessageSize)

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.GetLogger().Errorf("WebSocket error: %v", err)
			}
			break
		}

		// 处理客户端消息
		c.handleMessage(message)
	}
}

// WritePump 向 WebSocket 连接写入消息
func (c *Client) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub 关闭了通道
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// 将队列中的消息一起发送
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage 处理客户端消息
func (c *Client) handleMessage(message []byte) {
	var msg ClientMessage
	if err := json.Unmarshal(message, &msg); err != nil {
		logger.GetLogger().Errorf("Failed to unmarshal client message: %v", err)
		return
	}

	switch msg.Type {
	case "subscribe":
		// 订阅会话
		if msg.SessionID > 0 {
			c.hub.SubscribeSession(c, msg.SessionID)
			c.sendAck("subscribed", msg.SessionID)
		}

	case "unsubscribe":
		// 取消订阅会话
		if msg.SessionID > 0 {
			c.hub.UnsubscribeSession(c, msg.SessionID)
			c.sendAck("unsubscribed", msg.SessionID)
		}

	case "ping":
		// 响应 ping
		c.sendAck("pong", 0)

	default:
		logger.GetLogger().Warnf("Unknown message type: %s", msg.Type)
	}
}

// sendAck 发送确认消息
func (c *Client) sendAck(ackType string, sessionID uint) {
	ack := map[string]interface{}{
		"type":       ackType,
		"session_id": sessionID,
		"time":       time.Now(),
	}

	data, err := json.Marshal(ack)
	if err != nil {
		logger.GetLogger().Errorf("Failed to marshal ack: %v", err)
		return
	}

	select {
	case c.send <- data:
	default:
		logger.GetLogger().Warn("Client send channel full")
	}
}

// Send 发送消息到客户端
func (c *Client) Send(data []byte) error {
	select {
	case c.send <- data:
		return nil
	default:
		return websocket.ErrCloseSent
	}
}
