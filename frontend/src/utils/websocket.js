/**
 * WebSocket 客户端管理
 */
class WebSocketClient {
  constructor() {
    this.ws = null
    this.url = ''
    this.reconnectInterval = 5000
    this.reconnectTimer = null
    this.isManualClose = false
    this.listeners = new Map()
    this.sessionSubscriptions = new Set()
  }

  /**
   * 连接 WebSocket
   * @param {string} url WebSocket URL
   */
  connect(url) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      console.log('WebSocket already connected')
      return
    }

    this.url = url
    this.isManualClose = false

    try {
      this.ws = new WebSocket(url)
      this.setupEventHandlers()
    } catch (error) {
      console.error('Failed to create WebSocket:', error)
      this.scheduleReconnect()
    }
  }

  /**
   * 设置事件处理器
   */
  setupEventHandlers() {
    this.ws.onopen = () => {
      console.log('WebSocket connected')
      this.clearReconnectTimer()
      this.emit('connected')

      // 重新订阅之前的会话
      this.sessionSubscriptions.forEach(sessionId => {
        this.subscribe(sessionId)
      })
    }

    this.ws.onclose = (event) => {
      console.log('WebSocket closed:', event.code, event.reason)
      this.emit('disconnected')

      if (!this.isManualClose) {
        this.scheduleReconnect()
      }
    }

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error)
      this.emit('error', error)
    }

    this.ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)
        this.handleMessage(message)
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error)
      }
    }
  }

  /**
   * 处理接收到的消息
   * @param {object} message 消息对象
   */
  handleMessage(message) {
    const { type, data, time } = message

    // 触发对应类型的监听器
    this.emit(type, data, time)

    // 触发通用消息监听器
    this.emit('message', message)
  }

  /**
   * 发送消息
   * @param {object} message 消息对象
   */
  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message))
    } else {
      console.warn('WebSocket is not connected')
    }
  }

  /**
   * 订阅会话
   * @param {number} sessionId 会话ID
   */
  subscribe(sessionId) {
    this.sessionSubscriptions.add(sessionId)
    this.send({
      type: 'subscribe',
      session_id: sessionId
    })
  }

  /**
   * 取消订阅会话
   * @param {number} sessionId 会话ID
   */
  unsubscribe(sessionId) {
    this.sessionSubscriptions.delete(sessionId)
    this.send({
      type: 'unsubscribe',
      session_id: sessionId
    })
  }

  /**
   * 添加事件监听器
   * @param {string} event 事件名称
   * @param {function} callback 回调函数
   */
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, [])
    }
    this.listeners.get(event).push(callback)
  }

  /**
   * 移除事件监听器
   * @param {string} event 事件名称
   * @param {function} callback 回调函数
   */
  off(event, callback) {
    if (!this.listeners.has(event)) {
      return
    }

    const callbacks = this.listeners.get(event)
    const index = callbacks.indexOf(callback)
    if (index > -1) {
      callbacks.splice(index, 1)
    }
  }

  /**
   * 触发事件
   * @param {string} event 事件名称
   * @param  {...any} args 参数
   */
  emit(event, ...args) {
    if (!this.listeners.has(event)) {
      return
    }

    const callbacks = this.listeners.get(event)
    callbacks.forEach(callback => {
      try {
        callback(...args)
      } catch (error) {
        console.error(`Error in ${event} listener:`, error)
      }
    })
  }

  /**
   * 安排重连
   */
  scheduleReconnect() {
    this.clearReconnectTimer()
    this.reconnectTimer = setTimeout(() => {
      console.log('Attempting to reconnect WebSocket...')
      this.connect(this.url)
    }, this.reconnectInterval)
  }

  /**
   * 清除重连定时器
   */
  clearReconnectTimer() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }

  /**
   * 关闭连接
   */
  close() {
    this.isManualClose = true
    this.clearReconnectTimer()
    this.sessionSubscriptions.clear()

    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  /**
   * 获取连接状态
   */
  isConnected() {
    return this.ws && this.ws.readyState === WebSocket.OPEN
  }
}

// 创建单例
const wsClient = new WebSocketClient()

export default wsClient

