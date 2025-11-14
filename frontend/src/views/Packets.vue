<template>
  <div class="packets">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>数据包列表 - 会话 #{{ sessionId }}</span>
          <div>
            <el-dropdown @command="handleExport" style="margin-right: 10px">
              <el-button type="success">
                <el-icon><Download /></el-icon> 导出
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="pcap">导出为 PCAP</el-dropdown-item>
                  <el-dropdown-item command="csv">导出为 CSV</el-dropdown-item>
                  <el-dropdown-item command="json">导出为 JSON</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
            <el-button @click="goBack">
              <el-icon><ArrowLeft /></el-icon> 返回
            </el-button>
            <el-button type="primary" @click="loadPackets">
              <el-icon><Refresh /></el-icon> 刷新
            </el-button>
          </div>
        </div>
      </template>

      <!-- 会话信息 -->
      <el-descriptions v-if="session" :column="4" border style="margin-bottom: 20px">
        <el-descriptions-item label="会话名称">{{ session.name }}</el-descriptions-item>
        <el-descriptions-item label="类型">
          <el-tag>{{ session.type?.toUpperCase() }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusType(session.status)">{{ session.status }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="数据包数量">{{ session.packetCount || 0 }}</el-descriptions-item>
      </el-descriptions>

      <!-- 过滤器 -->
      <el-form :inline="true" style="margin-bottom: 20px">
        <el-form-item label="协议">
          <el-select v-model="filter.protocol" placeholder="全部协议" clearable style="width: 150px">
            <el-option label="TCP" value="TCP" />
            <el-option label="UDP" value="UDP" />
            <el-option label="HTTP" value="HTTP" />
            <el-option label="DNS" value="DNS" />
            <el-option label="ICMP" value="ICMP" />
            <el-option label="ARP" value="ARP" />
          </el-select>
        </el-form-item>
        <el-form-item label="源地址">
          <el-input v-model="filter.srcAddr" placeholder="源IP/地址" clearable style="width: 200px" />
        </el-form-item>
        <el-form-item label="目标地址">
          <el-input v-model="filter.dstAddr" placeholder="目标IP/地址" clearable style="width: 200px" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="applyFilter">应用过滤</el-button>
          <el-button @click="resetFilter">重置</el-button>
        </el-form-item>
      </el-form>

      <!-- 数据包表格 -->
      <el-table
        :data="packets"
        stripe
        border
        v-loading="loading"
        @row-click="viewPacketDetail"
        style="cursor: pointer"
        :row-class-name="getRowClassName"
      >
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="timestamp" label="时间戳" width="180">
          <template #default="{ row }">
            {{ formatTime(row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column prop="protocol" label="协议" width="100">
          <template #default="{ row }">
            <el-tag size="small">{{ row.protocol }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="分析结果" width="200">
          <template #default="{ row }">
            <div v-if="row.analysisResult">
              <el-tag size="small" type="success">
                {{ row.analysisResult.protocol || row.protocol }}
              </el-tag>
              <el-tag v-if="row.analysisResult.anomalies" size="small" type="danger" style="margin-left: 5px">
                异常
              </el-tag>
            </div>
            <el-tag v-else size="small" type="info">未分析</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="srcAddr" label="源地址" width="150" />
        <el-table-column prop="srcPort" label="源端口" width="100" />
        <el-table-column prop="dstAddr" label="目标地址" width="150" />
        <el-table-column prop="dstPort" label="目标端口" width="100" />
        <el-table-column prop="length" label="长度" width="100">
          <template #default="{ row }">
            {{ row.length }} bytes
          </template>
        </el-table-column>
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click.stop="viewPacketDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.pageSize"
        :page-sizes="[20, 50, 100, 200]"
        :total="pagination.total"
        layout="total, sizes, prev, pager, next, jumper"
        @size-change="loadPackets"
        @current-change="loadPackets"
        style="margin-top: 20px; justify-content: center"
      />
    </el-card>

    <!-- 数据包详情对话框 -->
    <el-dialog 
      v-model="detailVisible" 
      title="数据包详情" 
      width="70%"
      :close-on-click-modal="false"
    >
      <el-descriptions v-if="currentPacket" :column="2" border>
        <el-descriptions-item label="ID">{{ currentPacket.id }}</el-descriptions-item>
        <el-descriptions-item label="时间戳">{{ formatTime(currentPacket.timestamp) }}</el-descriptions-item>
        <el-descriptions-item label="协议">
          <el-tag>{{ currentPacket.protocol }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="长度">{{ currentPacket.length }} bytes</el-descriptions-item>
        <el-descriptions-item label="源地址">{{ currentPacket.srcAddr }}</el-descriptions-item>
        <el-descriptions-item label="源端口">{{ currentPacket.srcPort || 'N/A' }}</el-descriptions-item>
        <el-descriptions-item label="目标地址">{{ currentPacket.dstAddr }}</el-descriptions-item>
        <el-descriptions-item label="目标端口">{{ currentPacket.dstPort || 'N/A' }}</el-descriptions-item>
      </el-descriptions>

      <el-divider>协议分析结果</el-divider>
      <div v-if="currentPacket?.analysisResult">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="识别协议">
            <el-tag type="success">{{ currentPacket.analysisResult.protocol }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="版本" v-if="currentPacket.analysisResult.version">
            {{ currentPacket.analysisResult.version }}
          </el-descriptions-item>
          <el-descriptions-item label="方法" v-if="currentPacket.analysisResult.method">
            <el-tag>{{ currentPacket.analysisResult.method }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="URI" v-if="currentPacket.analysisResult.uri" :span="2">
            {{ currentPacket.analysisResult.uri }}
          </el-descriptions-item>
          <el-descriptions-item label="状态码" v-if="currentPacket.analysisResult.status_code">
            <el-tag :type="currentPacket.analysisResult.status_code >= 400 ? 'danger' : 'success'">
              {{ currentPacket.analysisResult.status_code }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="摘要" :span="2">
            {{ currentPacket.analysisResult.summary }}
          </el-descriptions-item>
        </el-descriptions>

        <!-- 异常检测结果 -->
        <div v-if="currentPacket.analysisResult.anomalies && currentPacket.analysisResult.anomalies.length > 0" style="margin-top: 15px;">
          <el-alert
            title="检测到异常"
            type="warning"
            :closable="false"
            style="margin-bottom: 10px"
          >
            <ul style="margin: 5px 0; padding-left: 20px;">
              <li v-for="(anomaly, index) in currentPacket.analysisResult.anomalies" :key="index">
                {{ anomaly }}
              </li>
            </ul>
          </el-alert>
        </div>

        <!-- 详细字段 -->
        <div v-if="currentPacket.analysisResult.fields && Object.keys(currentPacket.analysisResult.fields).length > 0" style="margin-top: 15px;">
          <el-divider content-position="left">详细字段</el-divider>
          <el-table :data="formatFields(currentPacket.analysisResult.fields)" border size="small">
            <el-table-column prop="key" label="字段" width="200" />
            <el-table-column prop="value" label="值" />
          </el-table>
        </div>
      </div>
      <div v-else style="color: #999; text-align: center; padding: 20px;">
        <p>暂无分析结果</p>
        <el-button size="small" type="primary" @click="analyzePacket" :loading="analyzing">
          立即分析
        </el-button>
      </div>

      <el-divider>原始数据 (Hex)</el-divider>
      <div v-if="currentPacket?.payload" style="background: #f5f5f5; padding: 10px; border-radius: 4px; max-height: 200px; overflow: auto; font-family: monospace; word-break: break-all;">
        {{ formatHex(currentPacket.payload) }}
      </div>
      <div v-else style="color: #999; text-align: center; padding: 20px;">暂无数据</div>

      <template #footer>
        <el-button @click="detailVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Download } from '@element-plus/icons-vue'
import axios from 'axios'

const route = useRoute()
const router = useRouter()

const sessionId = ref(route.params.id)
const session = ref(null)
const packets = ref([])
const loading = ref(false)
const detailVisible = ref(false)
const currentPacket = ref(null)
const analyzing = ref(false)

const filter = ref({
  protocol: route.query.protocol || '',
  srcAddr: route.query.srcAddr || '',
  dstAddr: route.query.dstAddr || ''
})

const pagination = ref({
  page: 1,
  pageSize: 50,
  total: 0
})

// 加载会话信息
const loadSession = async () => {
  try {
    const res = await axios.get(`/api/capture/sessions/${sessionId.value}`)
    // 标准响应格式: {success: true, data: {session: {...}}}
    session.value = res.data.data.session
  } catch (error) {
    ElMessage.error('加载会话信息失败')
  }
}

// 加载数据包列表
const loadPackets = async () => {
  loading.value = true
  try {
    const params = {
      page: pagination.value.page,
      page_size: pagination.value.pageSize
    }

    if (filter.value.protocol) params.protocol = filter.value.protocol
    if (filter.value.srcAddr) params.srcAddr = filter.value.srcAddr
    if (filter.value.dstAddr) params.dstAddr = filter.value.dstAddr

    console.log('=== loadPackets ===')
    console.log('filter:', filter.value)
    console.log('params:', params)

    const res = await axios.get(`/api/capture/sessions/${sessionId.value}/packets`, { params })
    console.log('response:', res.data)

    // 标准响应格式: {success: true, data: {packets: [...]}, meta: {total: 10, ...}}
    packets.value = res.data.data.packets || []
    pagination.value.total = res.data.meta?.total || 0
  } catch (error) {
    ElMessage.error('加载数据包失败: ' + (error.response?.data?.error || error.message))
  } finally {
    loading.value = false
  }
}

// 查看数据包详情
const viewPacketDetail = (packet) => {
  currentPacket.value = packet
  detailVisible.value = true
}

// 应用过滤
const applyFilter = () => {
  pagination.value.page = 1
  loadPackets()
}

// 重置过滤
const resetFilter = () => {
  filter.value = {
    protocol: '',
    srcAddr: '',
    dstAddr: ''
  }
  pagination.value.page = 1
  loadPackets()
}

// 返回
const goBack = () => {
  router.push('/capture')
}

// 导出数据
const handleExport = async (format) => {
  try {
    ElMessage.info(`正在导出为 ${format.toUpperCase()} 格式...`)

    const response = await axios.get(`/api/capture/sessions/${sessionId.value}/export`, {
      params: { format },
      responseType: 'blob'
    })

    // 创建下载链接
    const url = window.URL.createObjectURL(new Blob([response.data]))
    const link = document.createElement('a')
    link.href = url

    // 从响应头获取文件名
    const contentDisposition = response.headers['content-disposition']
    let filename = `session_${sessionId.value}.${format}`
    if (contentDisposition) {
      const filenameMatch = contentDisposition.match(/filename="?(.+)"?/)
      if (filenameMatch) {
        filename = filenameMatch[1]
      }
    }

    link.setAttribute('download', filename)
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)

    ElMessage.success('导出成功')
  } catch (error) {
    ElMessage.error('导出失败: ' + (error.response?.data?.error || error.message))
  }
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
    second: '2-digit',
    fractionalSecondDigits: 3
  })
}

// 格式化十六进制
const formatHex = (payload) => {
  if (!payload) return ''
  // 如果 payload 是 base64 编码的字符串
  if (typeof payload === 'string') {
    try {
      const bytes = atob(payload)
      let hex = ''
      for (let i = 0; i < bytes.length; i++) {
        const byte = bytes.charCodeAt(i).toString(16).padStart(2, '0')
        hex += byte + ' '
        if ((i + 1) % 16 === 0) hex += '\n'
      }
      return hex
    } catch (e) {
      return payload
    }
  }
  return payload
}

// 获取状态类型
const getStatusType = (status) => {
  const typeMap = {
    running: 'success',
    stopped: 'warning',
    completed: 'info'
  }
  return typeMap[status] || 'info'
}

// 获取行类名（异常数据包高亮）
const getRowClassName = ({ row }) => {
  if (row.analysisResult && row.analysisResult.anomalies && row.analysisResult.anomalies.length > 0) {
    return 'anomaly-row'
  }
  return ''
}

// 格式化字段为表格数据
const formatFields = (fields) => {
  if (!fields || typeof fields !== 'object') return []
  return Object.entries(fields).map(([key, value]) => ({
    key,
    value: typeof value === 'object' ? JSON.stringify(value) : String(value)
  }))
}

// 分析数据包
const analyzePacket = async () => {
  if (!currentPacket.value) return

  analyzing.value = true
  try {
    const res = await axios.get(`/api/analyze/packets/${currentPacket.value.id}/result`)
    currentPacket.value.analysisResult = res.data.analysis

    // 更新列表中的数据包
    const index = packets.value.findIndex(p => p.id === currentPacket.value.id)
    if (index !== -1) {
      packets.value[index].analysisResult = res.data.analysis
    }

    ElMessage.success('分析完成')
  } catch (error) {
    ElMessage.error('分析失败: ' + (error.response?.data?.error || error.message))
  } finally {
    analyzing.value = false
  }
}

onMounted(() => {
  loadSession()
  loadPackets()
})
</script>

<style scoped>
.packets {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

:deep(.anomaly-row) {
  background-color: #fef0f0 !important;
}

:deep(.anomaly-row:hover) {
  background-color: #fde2e2 !important;
}
</style>
