<template>
  <div class="scan">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>漏洞扫描配置</span>
          <el-button type="primary" @click="startScan">
            <el-icon><Search /></el-icon> 开始扫描
          </el-button>
        </div>
      </template>

      <el-form :model="scanForm" label-width="120px">
        <el-form-item label="目标地址">
          <el-input v-model="scanForm.target" placeholder="IP 地址或域名" />
        </el-form-item>

        <el-form-item label="端口范围">
          <el-input v-model="scanForm.portRange" placeholder="例如: 1-1024" />
        </el-form-item>

        <el-form-item label="扫描类型">
          <el-radio-group v-model="scanForm.scanType">
            <el-radio label="port">端口扫描</el-radio>
            <el-radio label="service">服务识别</el-radio>
            <el-radio label="vuln">漏洞检测</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card style="margin-top: 20px">
      <template #header>
        <span>扫描任务</span>
      </template>

      <el-empty v-if="!loading && tasks.length === 0" description="暂无扫描任务" />
      <el-table v-else :data="tasks" stripe v-loading="loading">
        <el-table-column prop="target" label="目标" />
        <el-table-column prop="scanType" label="类型" width="120" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" label="进度" width="150">
          <template #default="{ row }">
            <el-progress :percentage="row.progress" />
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'

const scanForm = ref({
  target: '',
  portRange: '1-1024',
  scanType: 'port'
})

const tasks = ref([])
const loading = ref(false)

// 加载扫描任务列表
const loadTasks = async () => {
  loading.value = true
  try {
    const res = await axios.get('/api/scan/tasks')
    tasks.value = res.data.data || []
  } catch (error) {
    console.error('Failed to load scan tasks:', error)
  } finally {
    loading.value = false
  }
}

const startScan = async () => {
  if (!scanForm.value.target) {
    ElMessage.warning('请输入目标地址')
    return
  }

  try {
    await axios.post('/api/scan/start', {
      target: scanForm.value.target,
      port_range: scanForm.value.portRange,
      scan_type: scanForm.value.scanType
    })

    ElMessage.success('扫描已启动')
    // 重新加载任务列表
    setTimeout(loadTasks, 1000)
  } catch (error) {
    ElMessage.error('启动扫描失败')
  }
}

const getStatusType = (status) => {
  const typeMap = {
    pending: 'info',
    running: 'success',
    completed: 'primary',
    failed: 'danger'
  }
  return typeMap[status] || 'info'
}

onMounted(() => {
  loadTasks()
  // 每10秒刷新任务列表
  setInterval(loadTasks, 10000)
})
</script>

<style scoped>
.scan {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
