<template>
  <div class="packets">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>数据包列表 - 会话 #{{ sessionId }}</span>
          <div>
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
        <el-descriptions-item label="数据包数量">{{ session.packet_count || 0 }}</el-descriptions-item>
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
        <el-table-column prop="src_addr" label="源地址" width="150" />
        <el-table-column prop="src_port" label="源端口" width="100" />
        <el-table-column prop="dst_addr" label="目标地址" width="150" />
        <el-table-column prop="dst_port" label="目标端口" width="100" />
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
        <el-descriptions-item label="源地址">{{ currentPacket.src_addr }}</el-descriptions-item>
        <el-descriptions-item label="源端口">{{ currentPacket.src_port || 'N/A' }}</el-descriptions-item>
        <el-descriptions-item label="目标地址">{{ currentPacket.dst_addr }}</el-descriptions-item>
        <el-descriptions-item label="目标端口">{{ currentPacket.dst_port || 'N/A' }}</el-descriptions-item>
      </el-descriptions>

      <el-divider>分析结果</el-divider>
      <pre v-if="currentPacket?.analysis_result" style="background: #f5f5f5; padding: 10px; border-radius: 4px; max-height: 300px; overflow: auto;">{{ JSON.stringify(currentPacket.analysis_result, null, 2) }}</pre>
      <div v-else style="color: #999; text-align: center; padding: 20px;">暂无分析结果</div>

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
import axios from 'axios'

const route = useRoute()
const router = useRouter()

const sessionId = ref(route.params.id)
const session = ref(null)
const packets = ref([])
const loading = ref(false)
const detailVisible = ref(false)
const currentPacket = ref(null)

const filter = ref({
  protocol: '',
  srcAddr: '',
  dstAddr: ''
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
    session.value = res.data
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
    if (filter.value.srcAddr) params.src_addr = filter.value.srcAddr
    if (filter.value.dstAddr) params.dst_addr = filter.value.dstAddr

    const res = await axios.get(`/api/capture/sessions/${sessionId.value}/packets`, { params })
    packets.value = res.data.data || []
    pagination.value.total = res.data.total || 0
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
</style>
