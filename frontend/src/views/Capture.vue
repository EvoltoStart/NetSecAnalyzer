<template>
  <div class="capture">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>数据采集配置</span>
          <el-button type="primary" :disabled="isCapturing" @click="startCapture">
            <el-icon><VideoPlay /></el-icon> 开始采集
          </el-button>
        </div>
      </template>

      <el-form :model="captureForm" label-width="120px">
        <el-form-item label="会话名称" required>
          <el-input v-model="captureForm.name" placeholder="请输入会话名称" clearable />
        </el-form-item>

        <el-form-item label="采集类型">
          <el-radio-group v-model="captureForm.type">
            <el-radio value="ip">IP 网络</el-radio>
            <el-radio value="can">CAN 总线</el-radio>
            <el-radio value="rs485">RS-485</el-radio>
          </el-radio-group>
        </el-form-item>

        <!-- IP 网络采集配置 -->
        <template v-if="captureForm.type === 'ip'">
          <el-form-item label="网络接口" required>
            <el-select v-model="captureForm.interface" placeholder="选择网络接口" filterable>
              <el-option
                v-for="iface in interfaces"
                :key="iface"
                :label="iface"
                :value="iface"
              />
            </el-select>
          </el-form-item>

          <el-form-item label="BPF 过滤器">
            <el-input
              v-model="captureForm.filter"
              placeholder="留空表示捕获所有流量"
              clearable
            >
              <template #append>
                <el-button @click="showFilterDialog = true">模板</el-button>
              </template>
            </el-input>
            <div style="font-size: 12px; color: #909399; margin-top: 5px;">
              常用: tcp port 80 | udp | host 192.168.1.1 | net 192.168.0.0/16
            </div>
          </el-form-item>

          <el-collapse v-model="activeCollapse">
            <el-collapse-item title="高级配置" name="advanced">
              <el-form-item label="混杂模式">
                <el-switch v-model="captureForm.promisc" />
                <span style="margin-left: 10px; color: #909399; font-size: 12px;">
                  开启后可捕获所有经过网卡的流量
                </span>
              </el-form-item>

              <el-form-item label="快照长度">
                <el-input-number v-model="captureForm.snaplen" :min="64" :max="65536" :step="1024" />
                <span style="margin-left: 10px; color: #909399; font-size: 12px;">
                  字节 (推荐: 65536，捕获完整数据包)
                </span>
              </el-form-item>

              <el-form-item label="缓冲区大小">
                <el-input-number v-model="captureForm.bufferSize" :min="1000" :max="1000000" :step="10000" />
                <span style="margin-left: 10px; color: #909399; font-size: 12px;">
                  数据包数量 (推荐: 50000)
                </span>
              </el-form-item>

              <el-form-item label="超时时间">
                <el-input-number v-model="captureForm.timeout" :min="1" :max="60" />
                <span style="margin-left: 10px; color: #909399; font-size: 12px;">
                  秒 (推荐: 3)
                </span>
              </el-form-item>
            </el-collapse-item>
          </el-collapse>
        </template>

        <!-- CAN 总线采集配置 -->
        <template v-if="captureForm.type === 'can'">
          <el-form-item label="CAN 接口" required>
            <el-select v-model="captureForm.canInterface" placeholder="选择CAN接口">
              <el-option label="can0" value="can0" />
              <el-option label="can1" value="can1" />
              <el-option label="vcan0 (虚拟)" value="vcan0" />
            </el-select>
          </el-form-item>

          <el-form-item label="波特率">
            <el-select v-model="captureForm.canBitrate" placeholder="选择波特率">
              <el-option label="125 Kbps" :value="125000" />
              <el-option label="250 Kbps" :value="250000" />
              <el-option label="500 Kbps (推荐)" :value="500000" />
              <el-option label="1 Mbps" :value="1000000" />
            </el-select>
          </el-form-item>

          <el-form-item label="CAN ID 过滤">
            <el-input
              v-model="captureForm.canFilter"
              placeholder="例如: 0x100 或 0x100-0x200"
              clearable
            />
            <div style="font-size: 12px; color: #909399; margin-top: 5px;">
              支持单个ID (0x123) 或范围 (0x100-0x200)，留空表示捕获所有
            </div>
          </el-form-item>

          <el-form-item label="缓冲区大小">
            <el-input-number v-model="captureForm.canBufferSize" :min="100" :max="100000" :step="1000" />
            <span style="margin-left: 10px; color: #909399; font-size: 12px;">
              CAN 帧数量 (推荐: 5000)
            </span>
          </el-form-item>
        </template>

        <!-- RS-485 采集配置 -->
        <template v-if="captureForm.type === 'rs485'">
          <el-form-item label="串口" required>
            <el-select v-model="captureForm.serialPort" placeholder="选择串口" filterable>
              <el-option
                v-for="port in serialPorts"
                :key="port"
                :label="port"
                :value="port"
              />
            </el-select>
            <el-button @click="loadSerialPorts" style="margin-left: 10px;" size="small">
              <el-icon><Refresh /></el-icon> 刷新
            </el-button>
          </el-form-item>

          <el-form-item label="波特率" required>
            <el-select v-model="captureForm.baudrate" placeholder="选择波特率">
              <el-option label="9600 (推荐)" :value="9600" />
              <el-option label="19200" :value="19200" />
              <el-option label="38400" :value="38400" />
              <el-option label="57600" :value="57600" />
              <el-option label="115200" :value="115200" />
            </el-select>
          </el-form-item>

          <el-form-item label="数据位">
            <el-radio-group v-model="captureForm.databits">
              <el-radio :value="7">7</el-radio>
              <el-radio :value="8">8 (推荐)</el-radio>
            </el-radio-group>
          </el-form-item>

          <el-form-item label="校验位">
            <el-select v-model="captureForm.parity">
              <el-option label="无 (N) - 推荐" value="N" />
              <el-option label="偶校验 (E)" value="E" />
              <el-option label="奇校验 (O)" value="O" />
            </el-select>
          </el-form-item>

          <el-form-item label="停止位">
            <el-radio-group v-model="captureForm.stopbits">
              <el-radio :value="1">1 (推荐)</el-radio>
              <el-radio :value="2">2</el-radio>
            </el-radio-group>
          </el-form-item>

          <el-divider>Modbus 配置（可选）</el-divider>

          <el-form-item label="协议类型">
            <el-radio-group v-model="captureForm.protocol">
              <el-radio value="modbus-rtu">Modbus RTU</el-radio>
              <el-radio value="modbus-ascii">Modbus ASCII</el-radio>
              <el-radio value="raw">原始数据</el-radio>
            </el-radio-group>
          </el-form-item>

          <el-form-item v-if="captureForm.protocol !== 'raw'" label="从站地址">
            <el-input-number v-model="captureForm.slaveId" :min="1" :max="247" />
            <span style="margin-left: 10px; color: #909399; font-size: 12px;">
              Modbus 从站地址 (1-247)
            </span>
          </el-form-item>
        </template>
      </el-form>
    </el-card>

    <el-card style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <span>采集会话列表</span>
          <el-button @click="loadSessions" :loading="sessionsLoading">
            <el-icon><Refresh /></el-icon> 刷新
          </el-button>
        </div>
      </template>

      <el-table :data="sessions" stripe v-loading="sessionsLoading">
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="name" label="名称" min-width="150" show-overflow-tooltip />
        <el-table-column prop="type" label="类型" width="100">
          <template #default="{ row }">
            <el-tag>{{ row.type.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="packetCount" label="数据包数量" width="120">
          <template #default="{ row }">
            {{ row.packetCount || 0 }}
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="开始时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.startTime) }}
          </template>
        </el-table-column>
        <el-table-column label="持续时间" width="120">
          <template #default="{ row }">
            {{ getDuration(row) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="280" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="row.status === 'running'"
              size="small"
              type="danger"
              @click="stopCapture(row.id)"
              :loading="stoppingSessionId === row.id"
            >
              <el-icon><VideoPause /></el-icon> 停止
            </el-button>
            <el-button size="small" @click="viewPackets(row.id)">
              <el-icon><View /></el-icon> 查看数据包
            </el-button>
            <el-button
              size="small"
              type="danger"
              @click="confirmDeleteSession(row)"
              :disabled="row.status === 'running'"
            >
              <el-icon><Delete /></el-icon> 删除
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <el-empty description="暂无采集会话" />
        </template>
      </el-table>
    </el-card>

    <!-- BPF 过滤器模板对话框 -->
    <el-dialog v-model="showFilterDialog" title="BPF 过滤器模板" width="600px">
      <el-table :data="filterTemplates" @row-click="selectFilterTemplate" style="cursor: pointer;">
        <el-table-column prop="name" label="名称" width="150" />
        <el-table-column prop="value" label="过滤器" />
        <el-table-column prop="desc" label="说明" width="180" />
      </el-table>
      <template #footer>
        <el-button @click="showFilterDialog = false">取消</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { VideoPlay, VideoPause, Refresh, View, Delete } from '@element-plus/icons-vue'
import axios from 'axios'
import wsClient from '@/utils/websocket'

const router = useRouter()

const captureForm = ref({
  name: '',
  type: 'ip',
  // IP 配置
  interface: '',
  filter: '',
  promisc: true,
  snaplen: 65536,
  bufferSize: 50000,
  timeout: 3,
  // CAN 配置
  canInterface: 'can0',
  canBitrate: 500000,
  canFilter: '',
  canBufferSize: 5000,
  // RS-485 配置
  serialPort: '/dev/ttyUSB0',
  baudrate: 9600,
  databits: 8,
  parity: 'N',
  stopbits: 1,
  protocol: 'modbus-rtu',
  slaveId: 1
})

const activeCollapse = ref([])
const showFilterDialog = ref(false)

const interfaces = ref([]) // 从后端动态加载
const serialPorts = ref(['/dev/ttyUSB0', '/dev/ttyUSB1', '/dev/ttyS0']) // 串口列表
const sessions = ref([])
const isCapturing = ref(false)
const sessionsLoading = ref(false)
const stoppingSessionId = ref(null)

// BPF 过滤器模板
const filterTemplates = [
  { name: 'HTTP 流量', value: 'tcp port 80 or tcp port 443', desc: '捕获 HTTP/HTTPS 流量' },
  { name: 'DNS 查询', value: 'udp port 53', desc: '捕获 DNS 查询' },
  { name: 'ICMP (Ping)', value: 'icmp', desc: '捕获 ICMP 协议' },
  { name: 'ARP 协议', value: 'arp', desc: '捕获 ARP 协议' },
  { name: 'TCP 流量', value: 'tcp', desc: '捕获所有 TCP 流量' },
  { name: 'UDP 流量', value: 'udp', desc: '捕获所有 UDP 流量' },
  { name: '特定主机', value: 'host 192.168.1.1', desc: '捕获特定主机的流量' },
  { name: '特定网段', value: 'net 192.168.0.0/16', desc: '捕获特定网段的流量' },
  { name: 'SSH 连接', value: 'tcp port 22', desc: '捕获 SSH 连接' },
  { name: 'FTP 连接', value: 'tcp port 21 or tcp port 20', desc: '捕获 FTP 连接' }
]

const loadInterfaces = async () => {
  try {
    const res = await axios.get('/api/capture/interfaces')
    // 标准响应格式: {success: true, data: {interfaces: [...]}}
    interfaces.value = res.data.data.interfaces || []
    // 自动选择第一个非特殊接口
    if (interfaces.value.length > 0) {
      const normalInterfaces = interfaces.value.filter(i =>
        !['any', 'lo', 'bluetooth-monitor', 'nflog', 'nfqueue', 'dbus-system', 'dbus-session'].includes(i)
      )
      captureForm.value.interface = normalInterfaces.length > 0 ? normalInterfaces[0] : interfaces.value[0]
    }
  } catch (error) {
    ElMessage.error('加载网络接口失败: ' + (error.response?.data?.error || error.message))
  }
}

const loadSessions = async () => {
  sessionsLoading.value = true
  try {
    const res = await axios.get('/api/capture/sessions')
    // 标准响应格式: {success: true, data: {sessions: [...]}, meta: {...}}
    sessions.value = res.data.data.sessions || []

    // 检查是否有正在运行的会话
    const runningSession = sessions.value.find(s => s.status === 'running')
    isCapturing.value = !!runningSession
  } catch (error) {
    ElMessage.error('加载会话列表失败: ' + (error.response?.data?.error || error.message))
  } finally {
    sessionsLoading.value = false
  }
}

// 加载串口列表
const loadSerialPorts = async () => {
  try {
    const res = await axios.get('/api/capture/serial-ports')
    // 标准响应格式: {success: true, data: {ports: [...]}}
    serialPorts.value = res.data.data.ports || ['/dev/ttyUSB0', '/dev/ttyUSB1', '/dev/ttyS0']
    ElMessage.success('串口列表已刷新')
  } catch (error) {
    ElMessage.warning('无法获取串口列表，使用默认列表')
  }
}

// 选择过滤器模板
const selectFilterTemplate = (row) => {
  captureForm.value.filter = row.value
  showFilterDialog.value = false
  ElMessage.success(`已应用模板: ${row.name}`)
}

const startCapture = async () => {
  console.log('=== startCapture called ===')
  console.log('captureForm:', captureForm.value)

  // 验证表单
  if (!captureForm.value.name || !captureForm.value.name.trim()) {
    ElMessage.warning('请输入会话名称')
    return
  }

  if (captureForm.value.type === 'ip' && !captureForm.value.interface) {
    ElMessage.warning('请选择网络接口')
    return
  }

  if (captureForm.value.type === 'can' && !captureForm.value.canInterface) {
    ElMessage.warning('请选择 CAN 接口')
    return
  }

  if (captureForm.value.type === 'rs485' && !captureForm.value.serialPort) {
    ElMessage.warning('请选择串口')
    return
  }

  // 检查是否已有运行中的会话
  if (isCapturing.value) {
    ElMessage.warning('已有采集任务正在运行，请先停止当前任务')
    return
  }

  try {
    let config = {}

    // 根据采集类型构建配置
    if (captureForm.value.type === 'ip') {
      config = {
        interface: captureForm.value.interface,
        promisc: captureForm.value.promisc,
        snaplen: captureForm.value.snaplen,
        buffer_size: captureForm.value.bufferSize,
        timeout: captureForm.value.timeout
      }
    } else if (captureForm.value.type === 'can') {
      config = {
        interface: captureForm.value.canInterface,
        bitrate: captureForm.value.canBitrate,
        filter: captureForm.value.canFilter,
        buffer_size: captureForm.value.canBufferSize
      }
    } else if (captureForm.value.type === 'rs485') {
      config = {
        port: captureForm.value.serialPort,
        baudrate: captureForm.value.baudrate,
        databits: captureForm.value.databits,
        parity: captureForm.value.parity,
        stopbits: captureForm.value.stopbits,
        protocol: captureForm.value.protocol,
        slave_id: captureForm.value.slaveId
      }
    }

    const response = await axios.post('/api/capture/start', {
      name: captureForm.value.name.trim(),
      type: captureForm.value.type,
      config: config,
      filter: captureForm.value.filter || ''
    })

    // 标准响应格式: {success: true, data: {message: "...", sessionId: 123}}
    ElMessage.success({
      message: `采集已启动！会话 ID: ${response.data.data.sessionId}`,
      duration: 3000
    })

    isCapturing.value = true
    await loadSessions()

    // 清空表单
    captureForm.value.name = ''
    captureForm.value.filter = ''
  } catch (error) {
    const errorMsg = error.response?.data?.error || error.message
    ElMessage.error({
      message: '启动采集失败: ' + errorMsg,
      duration: 5000
    })
    console.error('Start capture error:', error.response?.data)
  }
}

const stopCapture = async (sessionId) => {
  stoppingSessionId.value = sessionId
  try {
    await axios.post(`/api/capture/stop?session_id=${sessionId}`)
    ElMessage.success('采集已停止')
    isCapturing.value = false
    await loadSessions()
  } catch (error) {
    ElMessage.error('停止采集失败: ' + (error.response?.data?.error || error.message))
  } finally {
    stoppingSessionId.value = null
  }
}

// 确认删除会话
const confirmDeleteSession = async (session) => {
  try {
    await ElMessageBox.confirm(
      `确定要删除会话 "${session.name}" 吗？这将删除该会话的所有数据包记录。`,
      '删除确认',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
      }
    )
    await deleteSession(session.id)
  } catch (error) {
    // 用户取消删除
    if (error !== 'cancel') {
      console.error('Delete session error:', error)
    }
  }
}

// 删除会话
const deleteSession = async (sessionId) => {
  try {
    await axios.delete(`/api/capture/sessions/${sessionId}`)
    ElMessage.success('会话已删除')
    await loadSessions()
  } catch (error) {
    ElMessage.error('删除会话失败: ' + (error.response?.data?.error || error.message))
  }
}

const viewPackets = (sessionId) => {
  router.push(`/packets/${sessionId}`)
}

const getStatusType = (status) => {
  const typeMap = {
    running: 'success',
    stopped: 'warning',
    completed: 'info'
  }
  return typeMap[status] || 'info'
}

const getStatusText = (status) => {
  const textMap = {
    running: '运行中',
    stopped: '已停止',
    completed: '已完成'
  }
  return textMap[status] || status
}

// 格式化时间
const formatTime = (timestamp) => {
  if (!timestamp) return 'N/A'
  return new Date(timestamp).toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

// 计算持续时间
const getDuration = (session) => {
  if (!session.startTime) return 'N/A'

  const start = new Date(session.startTime)
  const end = session.endTime ? new Date(session.endTime) : new Date()

  const durationMs = end - start
  const seconds = Math.floor(durationMs / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`
  } else if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`
  } else {
    return `${seconds}s`
  }
}

// WebSocket 连接和监听
const setupWebSocket = () => {
  // 连接 WebSocket
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const wsUrl = `${protocol}//${window.location.hostname}:${window.location.port}/api/ws`
  wsClient.connect(wsUrl)

  // 监听连接状态
  wsClient.on('connected', () => {
    console.log('WebSocket connected')
  })

  wsClient.on('disconnected', () => {
    console.log('WebSocket disconnected')
  })

  // 监听实时数据包
  wsClient.on('packet', (data) => {
    // 更新对应会话的数据包计数
    const session = sessions.value.find(s => s.id === data.sessionId)
    if (session) {
      session.packetCount = (session.packetCount || 0) + 1
    }
  })

  // 监听统计信息
  wsClient.on('stats', (data) => {
    const session = sessions.value.find(s => s.id === data.sessionId)
    if (session) {
      session.packetCount = data.packetCount
    }
  })

  // 监听完成消息
  wsClient.on('completed', (data) => {
    const session = sessions.value.find(s => s.id === data.sessionId)
    if (session) {
      session.status = 'completed'
      session.packetCount = data.packetCount
    }
    ElMessage.success(`会话 ${data.sessionId} 采集完成`)
  })
}

// 自动刷新定时器
let refreshTimer = null

onMounted(() => {
  loadInterfaces()
  loadSessions()
  setupWebSocket()

  // 每 10 秒自动刷新会话列表（仅当有运行中的会话时）
  refreshTimer = setInterval(() => {
    if (isCapturing.value) {
      loadSessions()
    }
  }, 10000)
})

onUnmounted(() => {
  // 清理 WebSocket 连接
  wsClient.close()

  // 清理定时器
  if (refreshTimer) {
    clearInterval(refreshTimer)
  }
})
</script>

<style scoped>
.capture {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
