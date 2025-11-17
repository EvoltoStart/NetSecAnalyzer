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

      <el-form :model="scanForm" label-width="120px" :rules="formRules" ref="scanFormRef">
        <el-form-item label="任务名称" prop="name">
          <el-input v-model="scanForm.name" placeholder="输入任务名称（可选）" clearable />
        </el-form-item>

        <el-form-item label="网络类型" prop="networkType">
          <el-radio-group v-model="scanForm.networkType" @change="onNetworkTypeChange">
            <el-radio label="ip">IP 网络</el-radio>
            <el-radio label="can">CAN 总线</el-radio>
            <el-radio label="rs485">RS-485 总线</el-radio>
          </el-radio-group>
        </el-form-item>

        <!-- IP 网络配置 -->
        <template v-if="scanForm.networkType === 'ip'">
          <el-form-item label="目标地址" prop="target" required>
            <el-input
              v-model="scanForm.target"
              placeholder="例如: 192.168.1.1 或 example.com"
              clearable
            />
          </el-form-item>

          <el-form-item label="端口范围" prop="portRange">
            <el-input
              v-model="scanForm.portRange"
              placeholder="例如: 1-1024 或 80,443,8080"
              clearable
            />
          </el-form-item>

          <el-form-item label="扫描说明">
            <el-alert
              title="全面安全扫描"
              type="info"
              :closable="false"
              show-icon
            >
              <template #default>
                <div class="scan-description">
                  <p><strong>扫描内容：</strong>端口检测 → 服务识别 → 漏洞检测</p>
                  <p><strong>预计时间：</strong>3-5分钟（取决于目标响应速度和开放端口数量）</p>
                  <p><strong>扫描步骤：</strong></p>
                  <ul>
                    <li>🔍 检测指定端口范围内的开放端口</li>
                    <li>🔧 识别开放端口上运行的服务和版本</li>
                    <li>🛡️ 检测已知安全漏洞和配置问题</li>
                  </ul>
                </div>
              </template>
            </el-alert>
          </el-form-item>
        </template>

        <!-- CAN 总线配置 -->
        <template v-else-if="scanForm.networkType === 'can'">
          <el-form-item label="CAN 接口">
            <el-input v-model="scanForm.canInterface" placeholder="例如: can0" />
          </el-form-item>

          <el-form-item label="扫描时长">
            <el-input-number v-model="scanForm.canDuration" :min="10" :max="300" /> 秒
          </el-form-item>

          <el-form-item label="扫描类型">
            <el-radio-group v-model="scanForm.scanType">
              <el-radio label="can">被动扫描</el-radio>
            </el-radio-group>
          </el-form-item>
        </template>

        <!-- RS-485 总线配置 -->
        <template v-else-if="scanForm.networkType === 'rs485'">
          <el-form-item label="串口">
            <el-input v-model="scanForm.rs485Port" placeholder="例如: /dev/ttyUSB0" />
          </el-form-item>

          <el-form-item label="波特率">
            <el-select v-model="scanForm.rs485BaudRate">
              <el-option label="9600" :value="9600" />
              <el-option label="19200" :value="19200" />
              <el-option label="38400" :value="38400" />
              <el-option label="57600" :value="57600" />
              <el-option label="115200" :value="115200" />
            </el-select>
          </el-form-item>

          <el-form-item label="地址范围">
            <el-col :span="11">
              <el-input-number v-model="scanForm.rs485StartAddr" :min="1" :max="247" />
            </el-col>
            <el-col :span="2" style="text-align: center">-</el-col>
            <el-col :span="11">
              <el-input-number v-model="scanForm.rs485EndAddr" :min="1" :max="247" />
            </el-col>
          </el-form-item>

          <el-form-item label="扫描类型">
            <el-radio-group v-model="scanForm.scanType">
              <el-radio label="rs485">Modbus 设备扫描</el-radio>
            </el-radio-group>
          </el-form-item>
        </template>
      </el-form>
    </el-card>

    <el-card style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <span>扫描任务 ({{ tasks.length }})</span>
          <el-button size="small" @click="loadTasks">
            <el-icon><Refresh /></el-icon> 刷新
          </el-button>
        </div>
      </template>

      <el-empty v-if="!loading && tasks.length === 0" description="暂无扫描任务" />
      <el-table v-else :data="tasks" stripe v-loading="loading">
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="name" label="名称" width="150">
          <template #default="{ row }">
            {{ row.name || row.target }}
          </template>
        </el-table-column>
        <el-table-column prop="target" label="目标" />
        <el-table-column prop="scanType" label="类型" width="120">
          <template #default="{ row }">
            <el-tag size="small">{{ row.scanType }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="progress" label="进度" width="150">
          <template #default="{ row }">
            <el-progress :percentage="row.progress || 0" />
          </template>
        </el-table-column>
        <el-table-column prop="createdAt" label="创建时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.createdAt) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="primary" @click="viewResults(row.id)">查看结果</el-button>
            <el-button size="small" type="danger" @click="deleteTask(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search, Refresh } from '@element-plus/icons-vue'
import axios from 'axios'

const router = useRouter()

const scanFormRef = ref(null)

const scanForm = ref({
  name: '',
  networkType: 'ip',
  target: '',
  portRange: '1-1024',
  scanType: 'vuln', // 默认全面扫描
  // CAN 配置
  canInterface: 'can0',
  canDuration: 30,
  // RS-485 配置
  rs485Port: '/dev/ttyUSB0',
  rs485BaudRate: 9600,
  rs485StartAddr: 1,
  rs485EndAddr: 247
})

const formRules = {
  target: [
    { required: true, message: '请输入目标地址', trigger: 'blur' }
  ],
  portRange: [
    { required: true, message: '请输入端口范围', trigger: 'blur' }
  ]
}

// 网络类型切换
const onNetworkTypeChange = (type) => {
  if (type === 'can') {
    scanForm.value.scanType = 'can'
    scanForm.value.target = scanForm.value.canInterface
  } else if (type === 'rs485') {
    scanForm.value.scanType = 'rs485'
    scanForm.value.target = scanForm.value.rs485Port
  } else {
    scanForm.value.scanType = 'vuln' // IP网络默认全面扫描
  }
}

const tasks = ref([])
const loading = ref(false)

// 加载扫描任务列表
const loadTasks = async () => {
  loading.value = true
  try {
    const res = await axios.get('/api/scan/tasks')
    // 标准响应格式: {success: true, data: {tasks: [...]}, meta: {...}}
    tasks.value = res.data.data.tasks || []
  } catch (error) {
    console.error('加载任务列表失败:', error)
    ElMessage.error('加载任务列表失败: ' + (error.response?.data?.error || error.message))
  } finally {
    loading.value = false
  }
}

const startScan = async () => {
  // 验证输入
  if (!scanForm.value.target || scanForm.value.target.trim() === '') {
    ElMessage.warning('请输入目标地址')
    return
  }

  // 根据网络类型验证
  if (scanForm.value.networkType === 'ip') {
    if (!scanForm.value.portRange) {
      ElMessage.warning('请输入端口范围')
      return
    }
  } else if (scanForm.value.networkType === 'can') {
    if (!scanForm.value.canInterface) {
      ElMessage.warning('请输入 CAN 接口')
      return
    }
  } else if (scanForm.value.networkType === 'rs485') {
    if (!scanForm.value.rs485Port) {
      ElMessage.warning('请输入串口')
      return
    }
  }

  try {
    // 显示加载提示
    const loadingMsg = ElMessage.info('正在启动扫描...')

    const payload = {
      name: scanForm.value.name.trim() || undefined, // 添加任务名称字段
      target: scanForm.value.target.trim(),
      scan_type: scanForm.value.scanType,
      network_type: scanForm.value.networkType,
      config: {}
    }

    // 根据网络类型添加配置
    if (scanForm.value.networkType === 'ip') {
      payload.port_range = scanForm.value.portRange
    } else if (scanForm.value.networkType === 'can') {
      payload.config.interface = scanForm.value.canInterface
      payload.config.duration = scanForm.value.canDuration
      payload.target = scanForm.value.canInterface
    } else if (scanForm.value.networkType === 'rs485') {
      payload.config.port = scanForm.value.rs485Port
      payload.config.baud_rate = scanForm.value.rs485BaudRate
      payload.config.start_addr = scanForm.value.rs485StartAddr
      payload.config.end_addr = scanForm.value.rs485EndAddr
      payload.target = scanForm.value.rs485Port
    }

    console.log('发送扫描请求:', payload)

    const response = await axios.post('/api/scan/start', payload)

    console.log('扫描响应:', response.data)

    loadingMsg.close()

    // 标准响应格式: {success: true, data: {taskId: 123, message: "..."}}
    const taskId = response.data.data?.taskId || response.data.taskId

    ElMessage.success({
      message: `扫描已启动！任务 ID: ${taskId}`,
      duration: 3000
    })

    // 重新加载任务列表
    await loadTasks()
  } catch (error) {
    console.error('扫描启动失败:', error)
    console.error('错误详情:', error.response)

    let errorMsg = '未知错误'
    if (error.response?.data?.error) {
      errorMsg = error.response.data.error
    } else if (error.message) {
      errorMsg = error.message
    }

    ElMessage.error({
      message: `启动扫描失败: ${errorMsg}`,
      duration: 5000
    })
  }
}

// 查看扫描结果
const viewResults = (taskId) => {
  router.push(`/scan/results/${taskId}`)
}

// 删除任务
const deleteTask = async (taskId) => {
  try {
    await ElMessageBox.confirm('确定要删除此扫描任务吗？', '确认删除', {
      type: 'warning'
    })

    await axios.delete(`/api/scan/tasks/${taskId}`)
    ElMessage.success('删除成功')
    loadTasks()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('删除失败: ' + (error.response?.data?.error || error.message))
    }
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

// 格式化时间
const formatTime = (timeStr) => {
  if (!timeStr) return '-'
  try {
    const date = new Date(timeStr)
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })
  } catch (error) {
    return timeStr
  }
}

// 定时器引用
let refreshTimer = null

onMounted(() => {
  console.log('扫描页面已挂载，开始加载任务列表')
  loadTasks()
  // 每10秒刷新任务列表
  refreshTimer = setInterval(loadTasks, 10000)
})

onUnmounted(() => {
  // 清理定时器
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
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


/* 扫描说明样式 */
.scan-description {
  line-height: 1.6;
}

.scan-description p {
  margin: 8px 0;
}

.scan-description ul {
  margin: 8px 0;
  padding-left: 20px;
}

.scan-description li {
  margin: 4px 0;
  color: #606266;
}
</style>
