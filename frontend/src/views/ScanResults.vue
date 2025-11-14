<template>
  <div class="scan-results">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>扫描结果 - 任务 #{{ taskId }}</span>
          <div>
            <el-dropdown @command="handleExport" style="margin-right: 10px">
              <el-button type="success">
                <el-icon><Download /></el-icon> 导出
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="json">导出为 JSON</el-dropdown-item>
                  <el-dropdown-item command="csv">导出为 CSV</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
            <el-button @click="goBack">
              <el-icon><ArrowLeft /></el-icon> 返回
            </el-button>
            <el-button type="primary" @click="loadResults">
              <el-icon><Refresh /></el-icon> 刷新
            </el-button>
          </div>
        </div>
      </template>

      <!-- 任务信息 -->
      <el-descriptions v-if="task" :column="4" border style="margin-bottom: 20px">
        <el-descriptions-item label="任务名称">{{ task.name || 'N/A' }}</el-descriptions-item>
        <el-descriptions-item label="目标">{{ task.target }}</el-descriptions-item>
        <el-descriptions-item label="扫描类型">
          <el-tag>{{ task.scanType?.toUpperCase() }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusType(task.status)">{{ task.status }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="开始时间">{{ formatTime(task.startTime) }}</el-descriptions-item>
        <el-descriptions-item label="结束时间">{{ formatTime(task.endTime) }}</el-descriptions-item>
        <el-descriptions-item label="进度">
          <el-progress :percentage="task.progress || 0" />
        </el-descriptions-item>
        <el-descriptions-item label="结果数量">{{ results.length }}</el-descriptions-item>
      </el-descriptions>

      <!-- 统计卡片 -->
      <el-row :gutter="20" style="margin-bottom: 20px">
        <el-col :span="6">
          <el-card shadow="hover">
            <el-statistic title="开放端口" :value="stats.openPorts">
              <template #prefix>
                <el-icon color="#67C23A"><CircleCheck /></el-icon>
              </template>
            </el-statistic>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card shadow="hover">
            <el-statistic title="识别服务" :value="stats.services">
              <template #prefix>
                <el-icon color="#409EFF"><Service /></el-icon>
              </template>
            </el-statistic>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card shadow="hover">
            <el-statistic title="发现漏洞" :value="stats.vulnerabilities">
              <template #prefix>
                <el-icon color="#F56C6C"><Warning /></el-icon>
              </template>
            </el-statistic>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card shadow="hover">
            <el-statistic title="高危漏洞" :value="stats.criticalVulns">
              <template #prefix>
                <el-icon color="#E6A23C"><WarnTriangleFilled /></el-icon>
              </template>
            </el-statistic>
          </el-card>
        </el-col>
      </el-row>

      <!-- 结果标签页 -->
      <el-tabs v-model="activeTab">
        <!-- 端口扫描结果 -->
        <el-tab-pane label="端口扫描" name="ports">
          <el-table :data="portResults" stripe border v-loading="loading">
            <el-table-column prop="port" label="端口" width="100" />
            <el-table-column prop="protocol" label="协议" width="100">
              <template #default="{ row }">
                <el-tag size="small">{{ row.protocol }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="service" label="服务" width="150" />
            <el-table-column prop="version" label="版本" />
            <el-table-column prop="banner" label="Banner" show-overflow-tooltip />
          </el-table>
        </el-tab-pane>

        <!-- 漏洞列表 -->
        <el-tab-pane label="漏洞列表" name="vulnerabilities">
          <el-table :data="vulnResults" stripe border v-loading="loading">
            <el-table-column prop="port" label="端口" width="100" />
            <el-table-column prop="severity" label="严重程度" width="120">
              <template #default="{ row }">
                <el-tag :type="getSeverityType(row.severity)">{{ row.severity }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="title" label="漏洞标题" width="250" show-overflow-tooltip />
            <el-table-column prop="vulnType" label="类型" width="150" />
            <el-table-column prop="cve" label="CVE" width="150" />
            <el-table-column prop="cvss" label="CVSS" width="100">
              <template #default="{ row }">
                <el-tag v-if="row.cvss" :type="getCVSSType(row.cvss)">{{ row.cvss }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="120">
              <template #default="{ row }">
                <el-button size="small" @click="viewVulnDetail(row)">详情</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 所有结果 -->
        <el-tab-pane label="全部结果" name="all">
          <el-table :data="results" stripe border v-loading="loading">
            <el-table-column prop="id" label="ID" width="80" />
            <el-table-column prop="resultType" label="类型" width="120">
              <template #default="{ row }">
                <el-tag size="small">{{ row.resultType }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="port" label="端口" width="100" />
            <el-table-column prop="protocol" label="协议" width="100" />
            <el-table-column prop="service" label="服务" width="150" />
            <el-table-column prop="title" label="标题" show-overflow-tooltip />
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 漏洞详情对话框 -->
    <el-dialog v-model="detailVisible" title="漏洞详情" width="60%">
      <el-descriptions v-if="currentVuln" :column="2" border>
        <el-descriptions-item label="端口">{{ currentVuln.port }}</el-descriptions-item>
        <el-descriptions-item label="协议">{{ currentVuln.protocol }}</el-descriptions-item>
        <el-descriptions-item label="服务">{{ currentVuln.service }}</el-descriptions-item>
        <el-descriptions-item label="版本">{{ currentVuln.version }}</el-descriptions-item>
        <el-descriptions-item label="漏洞类型">{{ currentVuln.vulnType }}</el-descriptions-item>
        <el-descriptions-item label="严重程度">
          <el-tag :type="getSeverityType(currentVuln.severity)">{{ currentVuln.severity }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="CVE">{{ currentVuln.cve || 'N/A' }}</el-descriptions-item>
        <el-descriptions-item label="CVSS">
          <el-tag v-if="currentVuln.cvss" :type="getCVSSType(currentVuln.cvss)">{{ currentVuln.cvss }}</el-tag>
          <span v-else>N/A</span>
        </el-descriptions-item>
        <el-descriptions-item label="标题" :span="2">{{ currentVuln.title }}</el-descriptions-item>
        <el-descriptions-item label="描述" :span="2">
          <div style="white-space: pre-wrap">{{ currentVuln.description || 'N/A' }}</div>
        </el-descriptions-item>
        <el-descriptions-item label="解决方案" :span="2">
          <div style="white-space: pre-wrap">{{ currentVuln.solution || 'N/A' }}</div>
        </el-descriptions-item>
        <el-descriptions-item label="参考链接" :span="2">
          <div v-if="currentVuln.references">
            <a v-for="(ref, idx) in currentVuln.references.split(',')" :key="idx" :href="ref.trim()" target="_blank" style="display: block">
              {{ ref.trim() }}
            </a>
          </div>
          <span v-else>N/A</span>
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Download, ArrowLeft, Refresh, CircleCheck, Service, Warning, WarnTriangleFilled } from '@element-plus/icons-vue'
import axios from 'axios'

const route = useRoute()
const router = useRouter()

const taskId = ref(route.params.id)
const task = ref(null)
const results = ref([])
const loading = ref(false)
const activeTab = ref('ports')
const detailVisible = ref(false)
const currentVuln = ref(null)

// 计算统计数据
const stats = computed(() => {
  const openPorts = results.value.filter(r => r.resultType === 'port').length
  // 识别服务：统计有版本或 Banner 信息的端口
  const services = results.value.filter(r =>
    r.resultType === 'port' && (r.version || r.banner || r.resultType === 'service')
  ).length
  const vulnerabilities = results.value.filter(r => r.resultType === 'vulnerability').length
  const criticalVulns = results.value.filter(r =>
    r.resultType === 'vulnerability' && (r.severity === 'critical' || r.severity === 'high')
  ).length

  return { openPorts, services, vulnerabilities, criticalVulns }
})

// 端口扫描结果
const portResults = computed(() => {
  return results.value.filter(r => r.resultType === 'port' || r.resultType === 'service')
})

// 漏洞结果
const vulnResults = computed(() => {
  return results.value.filter(r => r.resultType === 'vulnerability')
})

// 加载扫描结果
const loadResults = async () => {
  loading.value = true
  try {
    const res = await axios.get(`/api/scan/tasks/${taskId.value}/results`)
    // 标准响应格式: {success: true, data: {task: {...}, results: [...]}}
    task.value = res.data.data.task
    results.value = res.data.data.results || []
  } catch (error) {
    ElMessage.error('加载扫描结果失败: ' + (error.response?.data?.error || error.message))
  } finally {
    loading.value = false
  }
}

// 查看漏洞详情
const viewVulnDetail = (vuln) => {
  currentVuln.value = vuln
  detailVisible.value = true
}

// 导出结果
const handleExport = async (format) => {
  try {
    ElMessage.info(`正在导出为 ${format.toUpperCase()} 格式...`)
    
    const response = await axios.get(`/api/scan/tasks/${taskId.value}/export`, {
      params: { format },
      responseType: 'blob'
    })
    
    const url = window.URL.createObjectURL(new Blob([response.data]))
    const link = document.createElement('a')
    link.href = url
    
    const contentDisposition = response.headers['content-disposition']
    let filename = `scan_task_${taskId.value}.${format}`
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

// 返回
const goBack = () => {
  router.push('/scan')
}

// 格式化时间
const formatTime = (timestamp) => {
  if (!timestamp) return 'N/A'
  return new Date(timestamp).toLocaleString('zh-CN')
}

// 获取状态类型
const getStatusType = (status) => {
  const typeMap = {
    running: 'primary',
    completed: 'success',
    failed: 'danger',
    stopped: 'warning'
  }
  return typeMap[status] || 'info'
}

// 获取严重程度类型
const getSeverityType = (severity) => {
  const typeMap = {
    critical: 'danger',
    high: 'danger',
    medium: 'warning',
    low: 'info',
    info: ''
  }
  return typeMap[severity] || 'info'
}

// 获取 CVSS 类型
const getCVSSType = (cvss) => {
  if (cvss >= 9.0) return 'danger'
  if (cvss >= 7.0) return 'danger'
  if (cvss >= 4.0) return 'warning'
  return 'info'
}

onMounted(() => {
  loadResults()
})
</script>

<style scoped>
.scan-results {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>

