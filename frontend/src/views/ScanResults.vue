<template>
  <div class="scan-results">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>扫描结果 - 任务 #{{ taskId }}</span>
          <div>
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
            <el-table-column prop="banner" label="Banner" show-overflow-tooltip>
              <template #default="{ row }">
                <span>{{ formatBanner(row.banner) }}</span>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 漏洞列表 -->
        <el-tab-pane label="漏洞列表" name="vulnerabilities">
          <div style="margin-bottom: 10px;">
            <el-alert 
              :title="`共发现 ${vulnResults.length} 个漏洞`" 
              type="info" 
              :closable="false"
              show-icon
            />
          </div>
          <el-table :data="vulnResults" stripe border v-loading="loading" :row-key="getRowKey">
            <el-table-column type="index" label="#" width="50" />
            <el-table-column prop="port" label="端口" width="100">
              <template #default="{ row }">
                <span>{{ row.port || 'N/A' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="severity" label="严重程度" width="120">
              <template #default="{ row }">
                <el-tag :type="getSeverityType(row.severity)">{{ row.severity || 'Unknown' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="title" label="漏洞标题" min-width="250" show-overflow-tooltip>
              <template #default="{ row }">
                <span>{{ row.title || 'N/A' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="vulnType" label="类型" width="150">
              <template #default="{ row }">
                <span>{{ row.vulnType || row.vuln_type || 'N/A' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="cve" label="CVE" width="150">
              <template #default="{ row }">
                <span>{{ row.cve || row.CVE || 'N/A' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="cvss" label="CVSS" width="100">
              <template #default="{ row }">
                <el-tag v-if="row.cvss" :type="getCVSSType(row.cvss)">{{ row.cvss }}</el-tag>
                <span v-else>N/A</span>
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
          <el-table :data="results" stripe border v-loading="loading" :row-class-name="getRowClassName">
            <el-table-column prop="id" label="ID" width="80" />
            <el-table-column prop="resultType" label="类型" width="120">
              <template #default="{ row }">
                <el-tag
                  size="small"
                  :type="getResultTypeTag(row.resultType)"
                >
                  {{ getResultTypeLabel(row.resultType) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="port" label="端口" width="100">
              <template #default="{ row }">
                <span v-if="row.port">{{ row.port }}</span>
                <span v-else style="color: #ccc;">-</span>
              </template>
            </el-table-column>
            <el-table-column prop="protocol" label="协议" width="100">
              <template #default="{ row }">
                <el-tag v-if="row.protocol" size="small">{{ row.protocol }}</el-tag>
                <span v-else style="color: #ccc;">-</span>
              </template>
            </el-table-column>
            <el-table-column prop="service" label="服务" width="150">
              <template #default="{ row }">
                <span v-if="row.service">{{ row.service }}</span>
                <span v-else style="color: #ccc;">-</span>
              </template>
            </el-table-column>
            <el-table-column label="标题/描述" show-overflow-tooltip>
              <template #default="{ row }">
                <span v-if="row.resultType === 'vulnerability'">
                  <el-tag
                    v-if="row.severity"
                    :type="getSeverityType(row.severity)"
                    size="small"
                    style="margin-right: 8px;"
                  >
                    {{ row.severity }}
                  </el-tag>
                  {{ row.title }}
                </span>
                <span v-else-if="row.banner" style="color: #909399;">
                  {{ formatBanner(row.banner) }}
                </span>
                <span v-else style="color: #ccc;">-</span>
              </template>
            </el-table-column>
            <el-table-column label="CVE/CVSS" width="150">
              <template #default="{ row }">
                <div v-if="row.resultType === 'vulnerability'">
                  <div v-if="row.cve && row.cve !== 'N/A'">
                    <el-tag type="danger" size="small">{{ row.cve }}</el-tag>
                  </div>
                  <div v-if="row.cvss" style="margin-top: 4px;">
                    <el-tag :type="getCVSSType(row.cvss)" size="small">
                      CVSS: {{ row.cvss }}
                    </el-tag>
                  </div>
                </div>
                <span v-else style="color: #ccc;">-</span>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <!-- 调试信息 -->
        <el-tab-pane label="调试信息" name="debug" v-if="showDebug">
          <el-card>
            <template #header>
              <span>漏洞数据调试</span>
            </template>
            <div style="margin-bottom: 20px;">
              <el-button @click="showDebug = !showDebug" size="small">
                {{ showDebug ? '隐藏' : '显示' }}调试信息
              </el-button>
            </div>
            <el-descriptions title="统计信息" :column="2" border>
              <el-descriptions-item label="总结果数">{{ results.length }}</el-descriptions-item>
              <el-descriptions-item label="漏洞数量">{{ vulnResults.length }}</el-descriptions-item>
              <el-descriptions-item label="端口数量">{{ portResults.length }}</el-descriptions-item>
              <el-descriptions-item label="服务数量">{{ results.filter(r => r.resultType === 'service').length }}</el-descriptions-item>
            </el-descriptions>
            <div style="margin-top: 20px;">
              <h4>漏洞原始数据：</h4>
              <el-table :data="vulnResults" border size="small" style="margin-bottom: 20px;">
                <el-table-column prop="id" label="ID" width="60" />
                <el-table-column prop="port" label="端口" width="80" />
                <el-table-column prop="title" label="标题" min-width="200" />
                <el-table-column prop="vulnType" label="类型" width="150" />
                <el-table-column prop="severity" label="严重程度" width="100" />
                <el-table-column prop="target" label="Target" width="150" />
              </el-table>
              <details>
                <summary>查看JSON格式数据</summary>
                <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px; overflow: auto; max-height: 400px;">{{ JSON.stringify(vulnResults, null, 2) }}</pre>
              </details>
            </div>
          </el-card>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 漏洞详情对话框 -->
    <el-dialog v-model="detailVisible" title="漏洞详情" width="70%">
      <el-descriptions v-if="currentVuln" :column="2" border>
        <el-descriptions-item label="端口">
          <el-tag type="info">{{ currentVuln.port || 'N/A' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="协议">
          <el-tag size="small">{{ getProtocolByPort(currentVuln.port) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="服务">
          <el-tag size="small" type="success">{{ getServiceByPort(currentVuln.port) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="版本">
          <span>{{ getVersionFromDescription(currentVuln.description) || 'N/A' }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="漏洞类型">
          <el-tag type="warning">{{ currentVuln.vulnType || currentVuln.vuln_type || 'N/A' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="严重程度">
          <el-tag :type="getSeverityType(currentVuln.severity)">
            {{ (currentVuln.severity || 'Unknown').toUpperCase() }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="风险等级">
          <el-rate 
            :model-value="getRiskLevel(currentVuln.severity)" 
            :max="5" 
            disabled 
            show-score
            score-template="{value}/5"
          />
        </el-descriptions-item>
        <!-- 只有当CVE存在且不为空时才显示 -->
        <template v-if="currentVuln.cve && currentVuln.cve !== 'N/A' && currentVuln.cve.trim()">
          <el-descriptions-item label="CVE编号">
            <el-tag type="danger">{{ currentVuln.cve }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="CVSS评分" v-if="currentVuln.cvss">
            <el-tag :type="getCVSSType(currentVuln.cvss)">{{ currentVuln.cvss }}/10.0</el-tag>
          </el-descriptions-item>
        </template>
        <el-descriptions-item label="漏洞标题" :span="2">
          <div style="font-weight: 600; color: #303133;">{{ currentVuln.title || 'N/A' }}</div>
        </el-descriptions-item>
        <el-descriptions-item label="详细描述" :span="2">
          <div style="white-space: pre-wrap; line-height: 1.6; padding: 12px; background: #f8f9fa; border-radius: 4px;">
            {{ currentVuln.description || '暂无详细描述' }}
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="修复建议" :span="2">
          <div style="white-space: pre-wrap; line-height: 1.6; padding: 12px; background: #f0f9ff; border-radius: 4px; border-left: 4px solid #409eff;">
            {{ currentVuln.solution || '暂无修复建议' }}
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="参考资料" :span="2">
          <div v-if="currentVuln.references && currentVuln.references !== 'N/A'">
            <a
              v-for="(ref, idx) in currentVuln.references.split(',')"
              :key="idx"
              :href="ref.trim()"
              target="_blank"
              style="display: block; color: #409eff; text-decoration: none; margin: 4px 0;"
            >
              <el-icon><Link /></el-icon> {{ ref.trim() }}
            </a>
          </div>
          <div v-else style="color: #909399;">
            <el-icon><InfoFilled /></el-icon> 暂无相关参考资料
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="发现时间" :span="2">
          <span style="color: #606266;">
            <el-icon><Clock /></el-icon>
            {{ formatTime(currentVuln.discoveredAt || currentVuln.created_at || new Date()) }}
          </span>
        </el-descriptions-item>
      </el-descriptions>
      
      <template #footer>
        <div style="text-align: right;">
          <el-button @click="detailVisible = false">关闭</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { ArrowLeft, Refresh, CircleCheck, Service, Warning, WarnTriangleFilled, Link, InfoFilled, Clock } from '@element-plus/icons-vue'
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
const showDebug = ref(true) // 默认显示调试信息

// 计算统计数据
const stats = computed(() => {
  // 去重统计开放端口（按端口号去重）
  const portSet = new Set()
  results.value.forEach(r => {
    if ((r.resultType === 'port' || r.resultType === 'service') && r.port) {
      portSet.add(r.port)
    }
  })
  const openPorts = portSet.size

  // 统计有服务识别信息的端口数量
  const serviceSet = new Set()
  results.value.forEach(r => {
    if ((r.resultType === 'port' || r.resultType === 'service') && 
        r.port && (r.service && r.service !== 'Unknown')) {
      serviceSet.add(r.port)
    }
  })
  const services = serviceSet.size

  // 统计漏洞数量
  const vulnerabilities = results.value.filter(r => r.resultType === 'vulnerability').length
  
  // 统计高危漏洞数量
  const criticalVulns = results.value.filter(r =>
    r.resultType === 'vulnerability' && (r.severity === 'critical' || r.severity === 'high')
  ).length

  return { openPorts, services, vulnerabilities, criticalVulns }
})

// 端口扫描结果（去重合并）
const portResults = computed(() => {
  const portMap = new Map()
  
  // 先处理端口扫描结果
  results.value.filter(r => r.resultType === 'port').forEach(r => {
    if (r.port) {
      portMap.set(r.port, {
        port: r.port,
        protocol: r.protocol || 'TCP',
        service: r.service || 'Unknown',
        version: r.version || '',
        banner: r.banner || '',
        state: r.state || 'open'
      })
    }
  })
  
  // 再用服务识别结果更新信息
  results.value.filter(r => r.resultType === 'service').forEach(r => {
    if (r.port && portMap.has(r.port)) {
      const existing = portMap.get(r.port)
      portMap.set(r.port, {
        ...existing,
        service: r.service || existing.service,
        version: r.version || existing.version,
        banner: r.banner || existing.banner
      })
    }
  })
  
  return Array.from(portMap.values()).sort((a, b) => a.port - b.port)
})

// 漏洞结果
const vulnResults = computed(() => {
  const vulns = results.value.filter(r => r.resultType === 'vulnerability')
  // 调试信息：打印漏洞数据结构
  console.log('漏洞数据:', vulns)
  return vulns
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

// 格式化 Banner 信息
const formatBanner = (banner) => {
  if (!banner) return ''
  
  // 如果是HTTP响应，只显示关键信息
  if (banner.includes('HTTP/') && banner.includes('<html>')) {
    const lines = banner.split('\n')
    const statusLine = lines.find(line => line.startsWith('HTTP/'))
    const serverLine = lines.find(line => line.toLowerCase().startsWith('server:'))
    
    let result = []
    if (statusLine) result.push(statusLine.trim())
    if (serverLine) result.push(serverLine.trim())
    
    return result.join(' | ') || banner.substring(0, 100) + '...'
  }
  
  // 其他Banner信息，限制长度
  return banner.length > 100 ? banner.substring(0, 100) + '...' : banner
}

// 获取表格行键
const getRowKey = (row) => {
  return row.id || `${row.port}-${row.title}-${Math.random()}`
}

// 获取结果类型标签颜色
const getResultTypeTag = (type) => {
  const typeMap = {
    'port': 'success',
    'service': 'primary',
    'vulnerability': 'danger',
    'can_id': 'warning',
    'modbus_device': 'info'
  }
  return typeMap[type] || ''
}

// 获取结果类型标签文本
const getResultTypeLabel = (type) => {
  const labelMap = {
    'port': '端口',
    'service': '服务',
    'vulnerability': '漏洞',
    'can_id': 'CAN ID',
    'modbus_device': 'Modbus设备'
  }
  return labelMap[type] || type
}

// 获取表格行样式
const getRowClassName = ({ row }) => {
  if (row.resultType === 'vulnerability') {
    if (row.severity === 'critical') return 'critical-row'
    if (row.severity === 'high') return 'high-row'
    if (row.severity === 'medium') return 'medium-row'
  }
  return ''
}

// 根据端口获取协议
const getProtocolByPort = (port) => {
  const protocolMap = {
    22: 'TCP',
    80: 'TCP', 
    443: 'TCP',
    139: 'TCP',
    445: 'TCP',
    21: 'TCP',
    23: 'TCP',
    53: 'UDP',
    3389: 'TCP'
  }
  return protocolMap[port] || 'TCP'
}

// 根据端口获取服务名
const getServiceByPort = (port) => {
  const serviceMap = {
    22: 'SSH',
    80: 'HTTP',
    443: 'HTTPS', 
    139: 'NetBIOS',
    445: 'SMB',
    21: 'FTP',
    23: 'Telnet',
    53: 'DNS',
    3389: 'RDP'
  }
  return serviceMap[port] || 'Unknown'
}

// 从描述中提取版本信息
const getVersionFromDescription = (description) => {
  if (!description) return null
  
  // 匹配常见的版本格式
  const patterns = [
    /version:\s*([^\s,]+)/i,
    /SSH-[\d.]+-([^\s]+)/i,
    /nginx\/([^\s]+)/i,
    /apache\/([^\s]+)/i,
    /OpenSSH_([^\s]+)/i
  ]
  
  for (const pattern of patterns) {
    const match = description.match(pattern)
    if (match) return match[1]
  }
  
  return null
}

// 获取风险等级（1-5星）
const getRiskLevel = (severity) => {
  const levelMap = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'info': 1
  }
  return levelMap[severity?.toLowerCase()] || 1
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

/* 漏洞行高亮样式 */
:deep(.critical-row) {
  background-color: #fef0f0 !important;
}

:deep(.critical-row:hover) {
  background-color: #fde2e2 !important;
}

:deep(.high-row) {
  background-color: #fdf6ec !important;
}

:deep(.high-row:hover) {
  background-color: #faecd8 !important;
}

:deep(.medium-row) {
  background-color: #fdf6ec !important;
}

:deep(.medium-row:hover) {
  background-color: #faecd8 !important;
}
</style>

