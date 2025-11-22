<template>
  <div class="analyze">
    <el-card>
      <template #header>
        <span>协议分析</span>
      </template>

      <el-table :data="protocols" stripe v-loading="loading">
        <el-table-column prop="name" label="协议" width="150" />
        <el-table-column prop="count" label="数据包数量" width="150" />
        <el-table-column prop="percentage" label="占比" width="120">
          <template #default="{ row }">
            {{ row.percentage }}%
          </template>
        </el-table-column>
        <el-table-column label="操作">
          <template #default="{ row }">
            <el-button size="small" @click="viewDetails(row.name)">
              查看详情
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 会话选择对话框 -->
    <el-dialog
      v-model="sessionDialogVisible"
      :title="`查看 ${selectedProtocol} 协议详情`"
      width="70%"
      @close="sessionDialogVisible = false"
    >
      <div class="session-selection">
        <p style="margin-bottom: 16px; color: #606266;">请选择要分析的数据采集会话：</p>
        
        <el-table
          :data="sessions"
          highlight-current-row
          @current-change="handleSessionSelect"
          style="width: 100%"
          max-height="400px"
          empty-text="暂无采集会话"
        >
          <el-table-column type="index" label="序号" width="60" :index="(index) => index + 1" />
          <el-table-column prop="name" label="会话名称" min-width="150" show-overflow-tooltip />
          <el-table-column prop="id" label="会话 ID" width="80" />
          <el-table-column prop="packetCount" label="数据包数量" width="120" sortable>
            <template #default="{ row }">
              <span :class="{ 'has-data': row.packetCount > 0 }">
                {{ row.packetCount || 0 }}
              </span>
            </template>
          </el-table-column>
          <el-table-column prop="status" label="状态" width="100">
            <template #default="{ row }">
              <el-tag :type="getStatusType(row.status)" size="small">
                {{ getStatusText(row.status) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="createdAt" label="创建时间" width="140">
            <template #default="{ row }">
              {{ formatTime(row.createdAt) }}
            </template>
          </el-table-column>
        </el-table>
      </div>
      
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="sessionDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="confirmSessionSelection" :disabled="!selectedSessionId">
            查看详情
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import axios from 'axios'

const router = useRouter()
const protocols = ref([])
const loading = ref(false)
const sessions = ref([])

// 会话选择对话框相关
const sessionDialogVisible = ref(false)
const selectedProtocol = ref('')
const selectedSessionId = ref(null)

// 加载协议统计数据
const loadProtocols = async () => {
  loading.value = true
  try {
    const res = await axios.get('/api/stats/protocol-distribution')
    // 标准响应格式: {success: true, data: {protocols: [...]}}
    if (res.data.data.protocols) {
      // 计算总数
      const total = res.data.data.protocols.reduce((sum, item) => sum + item.value, 0)

      // 转换格式并计算百分比
      protocols.value = res.data.data.protocols.map(item => ({
        name: item.name,
        count: item.value,
        percentage: total > 0 ? ((item.value / total) * 100).toFixed(1) : 0
      }))
    }
  } catch (error) {
    ElMessage.error('加载协议数据失败')
  } finally {
    loading.value = false
  }
}

// 加载会话列表
const loadSessions = async () => {
  try {
    const res = await axios.get('/api/capture/sessions')
    // 标准响应格式: {success: true, data: {sessions: [...]}, meta: {...}}
    sessions.value = res.data.data.sessions || []
  } catch (error) {
    console.error('加载会话列表失败:', error)
  }
}

// 查看协议详情
const viewDetails = (protocol) => {
  // 如果没有会话，提示用户
  if (sessions.value.length === 0) {
    ElMessage.warning('暂无采集会话，请先进行数据采集')
    return
  }

  // 如果只有一个会话，直接跳转
  if (sessions.value.length === 1) {
    router.push({
      path: `/packets/${sessions.value[0].id}`,
      query: { protocol }
    })
    return
  }

  // 如果有多个会话，显示选择对话框
  selectedProtocol.value = protocol
  selectedSessionId.value = null
  sessionDialogVisible.value = true
}

// 处理会话选择
const handleSessionSelect = (currentRow) => {
  selectedSessionId.value = currentRow?.id || null
}

// 确认会话选择
const confirmSessionSelection = () => {
  if (selectedSessionId.value) {
    router.push({
      path: `/packets/${selectedSessionId.value}`,
      query: { protocol: selectedProtocol.value }
    })
    sessionDialogVisible.value = false
  } else {
    ElMessage.warning('请选择一个会话')
  }
}

// 获取状态类型
const getStatusType = (status) => {
  const typeMap = {
    running: 'success',
    stopped: 'info',
    completed: 'primary',
    failed: 'danger'
  }
  return typeMap[status] || 'info'
}

// 获取状态文本
const getStatusText = (status) => {
  const textMap = {
    running: '运行中',
    stopped: '已停止',
    completed: '已完成',
    failed: '失败'
  }
  return textMap[status] || status
}

// 格式化时间
const formatTime = (timeStr) => {
  if (!timeStr) return '-'
  try {
    const date = new Date(timeStr)
    return date.toLocaleString('zh-CN', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    })
  } catch {
    return '-'
  }
}

onMounted(() => {
  loadProtocols()
  loadSessions()
  // 每30秒刷新一次
  setInterval(loadProtocols, 30000)
})
</script>

<style scoped>
.analyze {
  padding: 20px;
}

.session-selection {
  margin: 16px 0;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

/* 表格样式 */
:deep(.el-table__row) {
  cursor: pointer;
}

:deep(.el-table__row:hover) {
  background-color: #f5f7fa;
}

:deep(.current-row) {
  background-color: #ecf5ff !important;
}

/* 数据包数量高亮 */
.has-data {
  color: #67c23a;
  font-weight: 600;
}
</style>
