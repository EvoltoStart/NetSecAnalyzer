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
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRouter } from 'vue-router'
import axios from 'axios'

const router = useRouter()
const protocols = ref([])
const loading = ref(false)
const sessions = ref([])

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
const viewDetails = async (protocol) => {
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

  // 如果有多个会话，让用户选择
  try {
    const { value: sessionId } = await ElMessageBox.prompt(
      `请输入要查看的会话 ID（1-${sessions.value.length}）`,
      `查看 ${protocol} 协议详情`,
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        inputPattern: /^\d+$/,
        inputErrorMessage: '请输入有效的会话 ID'
      }
    )

    const session = sessions.value.find(s => s.id === parseInt(sessionId))
    if (session) {
      router.push({
        path: `/packets/${session.id}`,
        query: { protocol }
      })
    } else {
      ElMessage.error('会话不存在')
    }
  } catch {
    // 用户取消
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
</style>
