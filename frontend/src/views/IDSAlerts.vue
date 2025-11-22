<template>
  <div class="ids-alerts">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>IDS 告警管理</span>
          <el-space>
            <el-button @click="refreshData" :icon="Refresh" size="small" :loading="loading">刷新数据</el-button>
          </el-space>
        </div>
      </template>

      <!-- 统计卡片 -->
      <el-row :gutter="20" style="margin-bottom: 20px">
        <el-col :span="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <el-icon class="stat-icon" color="#f56c6c"><Warning /></el-icon>
              <div class="stat-text">
                <div class="stat-value">{{ stats.total || 0 }}</div>
                <div class="stat-label">总告警数</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <el-icon class="stat-icon" color="#e6a23c"><Bell /></el-icon>
              <div class="stat-text">
                <div class="stat-value">{{ getStatusCount('new') }}</div>
                <div class="stat-label">新告警</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <el-icon class="stat-icon" color="#409eff"><Check /></el-icon>
              <div class="stat-text">
                <div class="stat-value">{{ getStatusCount('acknowledged') }}</div>
                <div class="stat-label">已确认</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <el-icon class="stat-icon" color="#67c23a"><CircleCheck /></el-icon>
              <div class="stat-text">
                <div class="stat-value">{{ getStatusCount('resolved') }}</div>
                <div class="stat-label">已解决</div>
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>

      <!-- 过滤器 -->
      <el-row :gutter="20" style="margin-bottom: 20px">
        <el-col :span="24">
          <el-space wrap>
            <el-select
              v-model="filter.type"
              placeholder="告警类型"
              clearable
              style="width: 150px"
              @change="loadAlerts"
            >
              <el-option label="全部" value="" />
              <el-option label="端口扫描" value="port_scan" />
              <el-option label="DoS 攻击" value="dos" />
              <el-option label="暴力破解" value="brute_force" />
              <el-option label="SQL 注入" value="sql_injection" />
              <el-option label="XSS 攻击" value="xss" />
            </el-select>

            <el-select
              v-model="filter.severity"
              placeholder="严重程度"
              clearable
              style="width: 120px"
              @change="loadAlerts"
            >
              <el-option label="全部" value="" />
              <el-option label="低" value="low" />
              <el-option label="中" value="medium" />
              <el-option label="高" value="high" />
              <el-option label="严重" value="critical" />
            </el-select>

            <el-select
              v-model="filter.status"
              placeholder="状态"
              clearable
              style="width: 120px"
              @change="loadAlerts"
            >
              <el-option label="全部" value="" />
              <el-option label="新告警" value="new" />
              <el-option label="已确认" value="acknowledged" />
              <el-option label="已解决" value="resolved" />
              <el-option label="已忽略" value="ignored" />
            </el-select>

            <el-input
              v-model="filter.source"
              placeholder="来源 IP"
              clearable
              style="width: 150px"
              @keyup.enter="loadAlerts"
            />

            <el-date-picker
              v-model="filter.dateRange"
              type="datetimerange"
              range-separator="至"
              start-placeholder="开始时间"
              end-placeholder="结束时间"
              format="YYYY-MM-DD HH:mm:ss"
              value-format="YYYY-MM-DD HH:mm:ss"
              @change="loadAlerts"
              style="width: 350px"
            />

            <el-button type="primary" @click="loadAlerts" :icon="Search">搜索</el-button>
            <el-button @click="resetFilter" :icon="RefreshRight">重置</el-button>
          </el-space>
        </el-col>
      </el-row>

      <!-- 选择状态显示 -->
      <el-row style="margin-bottom: 10px" v-if="allSelectedAlerts.length > 0">
        <el-col :span="24">
          <el-alert
            :title="`已选择 ${allSelectedAlerts.length} 个告警（跨页面选择）`"
            type="info"
            :closable="false"
            show-icon
          />
        </el-col>
      </el-row>

      <!-- 批量操作 -->
      <el-row style="margin-bottom: 15px">
        <el-col :span="24">
          <el-space>
            <el-button
              @click="selectAllData"
              size="small"
              :icon="Select"
              :loading="selectAllLoading"
            >
              全选所有数据 ({{ pagination.total }})
            </el-button>
            <el-button
              @click="selectCurrentPage"
              size="small"
              :icon="Document"
            >
              选择当前页 ({{ alerts.length }})
            </el-button>
            <el-button
              @click="clearSelection"
              size="small"
              :icon="Close"
              :disabled="selectedAlerts.length === 0 && allSelectedAlerts.length === 0"
            >
              取消选择
            </el-button>
            <el-divider direction="vertical" />
            <el-button
              type="primary"
              :disabled="selectedAlerts.length === 0 && allSelectedAlerts.length === 0"
              @click="batchAcknowledge"
              size="small"
              :icon="Check"
            >
              批量确认 ({{ allSelectedAlerts.length > 0 ? allSelectedAlerts.length : selectedAlerts.length }})
            </el-button>
            <el-button
              type="success"
              :disabled="selectedAlerts.length === 0 && allSelectedAlerts.length === 0"
              @click="batchResolve"
              size="small"
              :icon="CircleCheck"
            >
              批量解决 ({{ allSelectedAlerts.length > 0 ? allSelectedAlerts.length : selectedAlerts.length }})
            </el-button>
            <el-button
              type="info"
              :disabled="selectedAlerts.length === 0 && allSelectedAlerts.length === 0"
              @click="batchIgnore"
              size="small"
              :icon="Hide"
            >
              批量忽略 ({{ allSelectedAlerts.length > 0 ? allSelectedAlerts.length : selectedAlerts.length }})
            </el-button>
            <el-button
              type="danger"
              :disabled="selectedAlerts.length === 0 && allSelectedAlerts.length === 0"
              @click="batchDelete"
              size="small"
              :icon="Delete"
            >
              批量删除 ({{ allSelectedAlerts.length > 0 ? allSelectedAlerts.length : selectedAlerts.length }})
            </el-button>
          </el-space>
        </el-col>
      </el-row>

      <!-- 告警列表 -->
      <el-table
        ref="tableRef"
        :data="alerts"
        v-loading="loading"
        @selection-change="handleSelectionChange"
        stripe
      >
        <el-table-column type="selection" width="55" />
        <el-table-column prop="id" label="ID" width="70" />
        
        <el-table-column label="类型" width="120">
          <template #default="{ row }">
            <el-tag size="small">{{ getAlertTypeText(row.type) }}</el-tag>
          </template>
        </el-table-column>
        
        <el-table-column label="严重程度" width="100">
          <template #default="{ row }">
            <el-tag :type="getSeverityTagType(row.severity)" size="small">
              {{ getSeverityText(row.severity) }}
            </el-tag>
          </template>
        </el-table-column>
        
        <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
        
        <el-table-column prop="source" label="来源" width="140" />
        <el-table-column prop="destination" label="目标" width="140" />
        
        <el-table-column label="端口" width="100">
          <template #default="{ row }">
            <span v-if="row.sourcePort || row.destinationPort">
              {{ row.sourcePort || '-' }} → {{ row.destinationPort || '-' }}
            </span>
            <span v-else>-</span>
          </template>
        </el-table-column>
        
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="getStatusTagType(row.status)" size="small">
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        
        <el-table-column prop="timestamp" label="发生时间" width="160">
          <template #default="{ row }">
            {{ formatTime(row.timestamp) }}
          </template>
        </el-table-column>
        
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-space>
              <el-button
                size="small"
                @click="viewDetail(row)"
                :icon="View"
                link
              >
                详情
              </el-button>
              
              <el-button
                v-if="row.status === 'new'"
                size="small"
                type="primary"
                @click="acknowledgeAlert(row)"
                link
              >
                确认
              </el-button>
              
              <el-button
                v-if="row.status === 'acknowledged'"
                size="small"
                type="success"
                @click="resolveAlert(row)"
                link
              >
                解决
              </el-button>
              
              <el-dropdown v-if="row.status !== 'ignored'">
                <el-button size="small" link>
                  更多<el-icon class="el-icon--right"><ArrowDown /></el-icon>
                </el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item @click="ignoreAlert(row)">
                      <el-icon><Hide /></el-icon>忽略
                    </el-dropdown-item>
                    <el-dropdown-item @click="addNotes(row)">
                      <el-icon><Edit /></el-icon>添加备注
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </el-space>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div style="margin-top: 20px; text-align: right">
        <el-pagination
          v-model:current-page="pagination.page"
          v-model:page-size="pagination.pageSize"
          :total="pagination.total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
          @current-change="loadAlerts"
          @size-change="loadAlerts"
        />
      </div>
    </el-card>

    <!-- 告警详情对话框 -->
    <el-dialog
      v-model="detailVisible"
      :title="`告警详情 #${currentAlert?.id || ''}`"
      width="80%"
      destroy-on-close
    >
      <div v-if="currentAlert">
        <!-- 基础信息卡片 -->
        <el-card class="alert-basic-info" style="margin-bottom: 20px">
          <template #header>
            <div class="card-header">
              <span>基础信息</span>
              <el-space>
                <el-tag :type="getSeverityTagType(currentAlert.severity)" size="large">
                  {{ getSeverityText(currentAlert.severity) }}
                </el-tag>
                <el-rate v-model="threatLevel" disabled show-score text-color="#ff9900" />
              </el-space>
            </div>
          </template>
          
          <el-descriptions :column="3" border>
            <el-descriptions-item label="告警ID">
              <el-tag>{{ currentAlert.id }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="攻击类型">
              <el-tag type="warning">{{ getAlertTypeText(currentAlert.type) }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="任务ID">
              <el-tag type="info">{{ currentAlert.taskId }}</el-tag>
            </el-descriptions-item>
          </el-descriptions>
        </el-card>

        <!-- 网络信息卡片 -->
        <el-card class="alert-network-info" style="margin-bottom: 20px">
          <template #header>网络信息</template>
          
          <el-descriptions :column="2" border>
            <el-descriptions-item label="攻击源">
              <div class="network-info">
                <el-tag type="danger">{{ currentAlert.source || '未知' }}</el-tag>
                <span v-if="currentAlert.sourcePort">:{{ currentAlert.sourcePort }}</span>
                <el-button v-if="currentAlert.source" size="small" link type="primary">
                  <el-icon><Search /></el-icon>查询IP
                </el-button>
              </div>
            </el-descriptions-item>
            <el-descriptions-item label="攻击目标">
              <div class="network-info">
                <el-tag>{{ currentAlert.destination || '未知' }}</el-tag>
                <span v-if="currentAlert.destinationPort">:{{ currentAlert.destinationPort }}</span>
              </div>
            </el-descriptions-item>
            <el-descriptions-item label="协议类型">
              <el-tag :type="getProtocolType(currentAlert.protocol)">
                {{ currentAlert.protocol || '未知' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="状态">
              <el-tag :type="getStatusTagType(currentAlert.status)">
                {{ getStatusText(currentAlert.status) }}
              </el-tag>
            </el-descriptions-item>
          </el-descriptions>
        </el-card>

        <!-- 攻击分析卡片 -->
        <el-card class="alert-analysis" style="margin-bottom: 20px">
          <template #header>攻击分析</template>
          
          <!-- 端口扫描专用分析 -->
          <div v-if="currentAlert.type === 'port_scan'">
            <el-row :gutter="20" style="margin-bottom: 20px">
              <el-col :span="8">
                <el-statistic title="扫描端口数" :value="getDetail('ports_scanned') || 0" />
              </el-col>
              <el-col :span="8">
                <el-statistic title="扫描速率" :value="getScanRate()" suffix="端口/秒" :precision="1" />
              </el-col>
              <el-col :span="8">
                <el-statistic title="持续时间" :value="getDetail('time_window') || '未知'" />
              </el-col>
            </el-row>
            
            <el-divider>端口分析</el-divider>
            <div class="port-analysis">
              <el-descriptions :column="1" border>
                <el-descriptions-item label="扫描模式">
                  <el-tag>{{ getScanPattern() }}</el-tag>
                </el-descriptions-item>
                <el-descriptions-item label="常见服务端口">
                  <div v-if="getCommonPorts().length > 0">
                    <el-tag 
                      v-for="port in getCommonPorts()" 
                      :key="port"
                      type="success"
                      size="small"
                      style="margin: 2px"
                    >
                      {{ port }}
                    </el-tag>
                  </div>
                  <span v-else>无</span>
                </el-descriptions-item>
                <el-descriptions-item label="高风险端口">
                  <div v-if="getHighRiskPorts().length > 0">
                    <el-tag 
                      v-for="port in getHighRiskPorts()" 
                      :key="port"
                      type="danger"
                      size="small"
                      style="margin: 2px"
                    >
                      {{ port }}
                    </el-tag>
                  </div>
                  <span v-else>无</span>
                </el-descriptions-item>
              </el-descriptions>
            </div>
          </div>
          
          <!-- DoS攻击专用分析 -->
          <div v-else-if="currentAlert.type === 'dos'">
            <el-row :gutter="20" style="margin-bottom: 20px">
              <el-col :span="8">
                <el-statistic title="请求总数" :value="getDetail('request_count') || 0" />
              </el-col>
              <el-col :span="8">
                <el-statistic title="请求速率" :value="getDetail('rate_per_sec') || 0" suffix="req/s" :precision="1" />
              </el-col>
              <el-col :span="8">
                <el-statistic title="时间窗口" :value="getDetail('time_window') || '未知'" />
              </el-col>
            </el-row>
            
            <el-descriptions :column="1" border>
              <el-descriptions-item label="攻击强度">
                <el-progress 
                  :percentage="getAttackIntensity()" 
                  :color="getIntensityColor(getAttackIntensity())"
                />
              </el-descriptions-item>
              <el-descriptions-item label="阈值对比">
                当前: {{ getDetail('request_count') }} | 阈值: {{ getDetail('threshold') }}
              </el-descriptions-item>
            </el-descriptions>
          </div>

          <!-- 通用详细信息 -->
          <div v-else>
            <el-descriptions :column="2" border>
              <el-descriptions-item
                v-for="(value, key) in currentAlert.details"
                :key="key"
                :label="formatDetailKey(key)"
              >
                {{ formatDetailValue(value) }}
              </el-descriptions-item>
            </el-descriptions>
          </div>
        </el-card>

        <!-- 时间线分析 -->
        <el-card class="alert-timeline" style="margin-bottom: 20px">
          <template #header>时间线分析</template>
          
          <el-timeline>
            <el-timeline-item timestamp="攻击开始" type="primary">
              {{ formatTime(currentAlert.timestamp) }}
            </el-timeline-item>
            <el-timeline-item timestamp="告警生成" type="success">
              {{ formatTime(currentAlert.createdAt) }}
            </el-timeline-item>
            <el-timeline-item timestamp="响应延迟" type="info">
              {{ getResponseDelay() }}
            </el-timeline-item>
          </el-timeline>
        </el-card>

        <!-- 建议措施 -->
        <el-card class="alert-recommendations">
          <template #header>建议措施</template>
          
          <div v-for="recommendation in getRecommendations()" :key="recommendation.type">
            <el-alert 
              :title="recommendation.title"
              :description="recommendation.description"
              :type="recommendation.level"
              show-icon
              style="margin-bottom: 10px"
            />
          </div>
        </el-card>

        <!-- 处理记录 -->
        <div v-if="currentAlert.acknowledgedBy || currentAlert.resolvedBy" style="margin-top: 20px">
          <el-divider>处理记录</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item v-if="currentAlert.acknowledgedBy" label="确认人">
              {{ currentAlert.acknowledgedBy }}
            </el-descriptions-item>
            <el-descriptions-item v-if="currentAlert.acknowledgedAt" label="确认时间">
              {{ formatTime(currentAlert.acknowledgedAt) }}
            </el-descriptions-item>
            <el-descriptions-item v-if="currentAlert.resolvedBy" label="解决人">
              {{ currentAlert.resolvedBy }}
            </el-descriptions-item>
            <el-descriptions-item v-if="currentAlert.resolvedAt" label="解决时间">
              {{ formatTime(currentAlert.resolvedAt) }}
            </el-descriptions-item>
            <el-descriptions-item v-if="currentAlert.notes" label="备注" :span="2">
              {{ currentAlert.notes }}
            </el-descriptions-item>
          </el-descriptions>
        </div>
      </div>

      <template #footer>
        <el-space>
          <el-button @click="detailVisible = false">关闭</el-button>
          <el-button
            v-if="currentAlert?.status === 'new'"
            type="primary"
            @click="acknowledgeAlert(currentAlert)"
          >
            确认告警
          </el-button>
          <el-button
            v-if="currentAlert?.status === 'acknowledged'"
            type="success"
            @click="resolveAlert(currentAlert)"
          >
            解决告警
          </el-button>
        </el-space>
      </template>
    </el-dialog>

    <!-- 添加备注对话框 -->
    <el-dialog
      v-model="notesVisible"
      title="添加备注"
      width="50%"
    >
      <el-form>
        <el-form-item label="备注内容">
          <el-input
            v-model="notes"
            type="textarea"
            :rows="4"
            placeholder="请输入备注内容..."
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="notesVisible = false">取消</el-button>
        <el-button type="primary" @click="saveNotes">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Refresh, Warning, Bell, Check, CircleCheck,
  Search, RefreshRight, View, ArrowDown, Hide, Edit,
  Select, Close, Delete, Document
} from '@element-plus/icons-vue'
import axios from 'axios'

// 数据状态
const alerts = ref([])
const stats = ref({})
const loading = ref(false)
const selectAllLoading = ref(false)
const selectedAlerts = ref([])
const allSelectedAlerts = ref([]) // 存储所有选中的告警（跨页面）

// 过滤器
const filter = ref({
  type: '',
  severity: '',
  status: '',
  source: '',
  dateRange: null
})

// 分页
const pagination = ref({
  page: 1,
  pageSize: 20,
  total: 0
})

// 对话框状态
const detailVisible = ref(false)
const notesVisible = ref(false)
const currentAlert = ref(null)
const notes = ref('')

// 定时器
let refreshTimer = null

// 计算属性
const getStatusCount = computed(() => {
  return (status) => {
    if (!stats.value.byStatus) return 0
    const stat = stats.value.byStatus.find(s => s.status === status)
    return stat ? stat.count : 0
  }
})

// 加载告警列表
const loadAlerts = async () => {
  loading.value = true
  try {
    const params = {
      page: pagination.value.page,
      page_size: pagination.value.pageSize
    }

    if (filter.value.type) params.type = filter.value.type
    if (filter.value.severity) params.severity = filter.value.severity
    if (filter.value.status) params.status = filter.value.status
    if (filter.value.source) params.source = filter.value.source
    if (filter.value.dateRange && filter.value.dateRange.length === 2) {
      params.start_time = filter.value.dateRange[0]
      params.end_time = filter.value.dateRange[1]
    }

    const res = await axios.get('/api/defense/ids/alerts', { params })
    alerts.value = res.data.data.alerts || []
    pagination.value.total = res.data.meta.total || 0
  } catch (error) {
    console.error('Failed to load alerts:', error)
    ElMessage.error('加载告警失败')
  } finally {
    loading.value = false
  }
}

// 加载统计信息
const loadStats = async () => {
  try {
    const res = await axios.get('/api/defense/ids/alerts/stats')
    stats.value = res.data.data || {}
  } catch (error) {
    console.error('Failed to load stats:', error)
  }
}

// 刷新数据（告警+统计）
const refreshData = async () => {
  try {
    await Promise.all([loadAlerts(), loadStats()])
    ElMessage.success('数据已刷新')
  } catch (error) {
    console.error('Failed to refresh data:', error)
    ElMessage.error('刷新数据失败')
  }
}

// 重置过滤器
const resetFilter = () => {
  filter.value = {
    type: '',
    severity: '',
    status: '',
    source: '',
    dateRange: null
  }
  pagination.value.page = 1
  loadAlerts()
}

// 选择变化
const handleSelectionChange = (selection) => {
  selectedAlerts.value = selection
}

// 表格引用
const tableRef = ref()

// 全选所有数据（跨页面）
const selectAllData = async () => {
  selectAllLoading.value = true
  try {
    // 获取所有告警数据（不分页）
    const params = new URLSearchParams()
    
    // 应用当前过滤条件
    if (filter.value.type) params.append('type', filter.value.type)
    if (filter.value.severity) params.append('severity', filter.value.severity)
    if (filter.value.status) params.append('status', filter.value.status)
    if (filter.value.source) params.append('source', filter.value.source)
    if (filter.value.dateRange && filter.value.dateRange.length === 2) {
      params.append('start_time', filter.value.dateRange[0])
      params.append('end_time', filter.value.dateRange[1])
    }
    
    // 获取所有数据，不分页
    params.append('page', '1')
    params.append('page_size', '999999') // 获取所有数据
    
    const res = await axios.get(`/api/defense/ids/alerts?${params}`)
    const allAlerts = res.data.data.alerts || []
    
    // 存储所有选中的告警
    allSelectedAlerts.value = [...allAlerts]
    
    // 更新当前页面的选择状态（只选择当前页面中存在的告警）
    const currentPageSelectedAlerts = allAlerts.filter(alert => 
      alerts.value.some(currentAlert => currentAlert.id === alert.id)
    )
    selectedAlerts.value = [...currentPageSelectedAlerts]
    
    // 更新表格选择状态
    if (tableRef.value) {
      tableRef.value.clearSelection()
      currentPageSelectedAlerts.forEach(alert => {
        tableRef.value.toggleRowSelection(alert, true)
      })
    }
    
    ElMessage.success(`已选择 ${allSelectedAlerts.value.length} 个告警`)
    
  } catch (error) {
    console.error('Failed to select all data:', error)
    ElMessage.error('全选失败')
  } finally {
    selectAllLoading.value = false
  }
}

// 选择当前页面
const selectCurrentPage = () => {
  if (tableRef.value) {
    tableRef.value.toggleAllSelection()
  }
}

// 取消选择
const clearSelection = () => {
  allSelectedAlerts.value = []
  selectedAlerts.value = []
  if (tableRef.value) {
    tableRef.value.clearSelection()
  }
}

// 查看详情
const viewDetail = (alert) => {
  currentAlert.value = alert
  detailVisible.value = true
}

// 确认告警
const acknowledgeAlert = async (alert) => {
  try {
    await axios.put(`/api/defense/ids/alerts/${alert.id}`, {
      status: 'acknowledged',
      acknowledgedBy: 'admin'
    })
    ElMessage.success('告警已确认')
    loadAlerts()
    loadStats()
    if (detailVisible.value) {
      detailVisible.value = false
    }
  } catch (error) {
    console.error('Failed to acknowledge alert:', error)
    ElMessage.error('确认告警失败')
  }
}

// 解决告警
const resolveAlert = async (alert) => {
  try {
    await axios.put(`/api/defense/ids/alerts/${alert.id}`, {
      status: 'resolved',
      resolvedBy: 'admin'
    })
    ElMessage.success('告警已解决')
    loadAlerts()
    loadStats()
    if (detailVisible.value) {
      detailVisible.value = false
    }
  } catch (error) {
    console.error('Failed to resolve alert:', error)
    ElMessage.error('解决告警失败')
  }
}

// 忽略告警
const ignoreAlert = async (alert) => {
  try {
    await ElMessageBox.confirm('确认忽略此告警？', '确认忽略', {
      confirmButtonText: '确认',
      cancelButtonText: '取消',
      type: 'warning'
    })

    await axios.put(`/api/defense/ids/alerts/${alert.id}`, {
      status: 'ignored'
    })
    ElMessage.success('告警已忽略')
    loadAlerts()
    loadStats()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to ignore alert:', error)
      ElMessage.error('忽略告警失败')
    }
  }
}

// 添加备注
const addNotes = (alert) => {
  currentAlert.value = alert
  notes.value = alert.notes || ''
  notesVisible.value = true
}

// 保存备注
const saveNotes = async () => {
  if (!currentAlert.value) return

  try {
    await axios.put(`/api/defense/ids/alerts/${currentAlert.value.id}`, {
      status: currentAlert.value.status,
      notes: notes.value
    })
    ElMessage.success('备注已保存')
    notesVisible.value = false
    loadAlerts()
  } catch (error) {
    console.error('Failed to save notes:', error)
    ElMessage.error('保存备注失败')
  }
}

// 批量确认
const batchAcknowledge = async () => {
  const targetAlerts = allSelectedAlerts.value.length > 0 ? allSelectedAlerts.value : selectedAlerts.value
  if (targetAlerts.length === 0) return

  console.log('批量确认 - 跨页面选择数量:', allSelectedAlerts.value.length)
  console.log('批量确认 - 当前页选择数量:', selectedAlerts.value.length)
  console.log('批量确认 - 实际处理数量:', targetAlerts.length)

  try {
    await ElMessageBox.confirm(
      `确认批量确认 ${targetAlerts.length} 个告警？${allSelectedAlerts.value.length > 0 ? '（跨页面选择）' : '（当前页选择）'}`, 
      '批量确认', 
      {
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    for (const alert of targetAlerts) {
      if (alert.status === 'new') {
        await axios.put(`/api/defense/ids/alerts/${alert.id}`, {
          status: 'acknowledged',
          acknowledgedBy: 'admin'
        })
      }
    }

    ElMessage.success(`已确认 ${targetAlerts.length} 个告警`)
    
    // 清空选择并刷新数据
    allSelectedAlerts.value = []
    selectedAlerts.value = []
    loadAlerts()
    loadStats()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to batch acknowledge:', error)
      ElMessage.error('批量确认失败')
    }
  }
}

// 批量解决
const batchResolve = async () => {
  const targetAlerts = allSelectedAlerts.value.length > 0 ? allSelectedAlerts.value : selectedAlerts.value
  if (targetAlerts.length === 0) return

  try {
    await ElMessageBox.confirm(`确认批量解决 ${targetAlerts.length} 个告警？`, '批量解决', {
      confirmButtonText: '确认',
      cancelButtonText: '取消',
      type: 'warning'
    })

    for (const alert of targetAlerts) {
      if (alert.status === 'acknowledged' || alert.status === 'new') {
        await axios.put(`/api/defense/ids/alerts/${alert.id}`, {
          status: 'resolved',
          resolvedBy: 'admin'
        })
      }
    }

    ElMessage.success(`已解决 ${targetAlerts.length} 个告警`)
    
    // 清空选择并刷新数据
    allSelectedAlerts.value = []
    selectedAlerts.value = []
    loadAlerts()
    loadStats()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to batch resolve:', error)
      ElMessage.error('批量解决失败')
    }
  }
}

// 批量忽略
const batchIgnore = async () => {
  const targetAlerts = allSelectedAlerts.value.length > 0 ? allSelectedAlerts.value : selectedAlerts.value
  if (targetAlerts.length === 0) return

  try {
    await ElMessageBox.confirm(`确认批量忽略 ${targetAlerts.length} 个告警？`, '批量忽略', {
      confirmButtonText: '确认',
      cancelButtonText: '取消',
      type: 'warning'
    })

    for (const alert of targetAlerts) {
      if (alert.status !== 'ignored') {
        await axios.put(`/api/defense/ids/alerts/${alert.id}`, {
          status: 'ignored'
        })
      }
    }

    ElMessage.success(`已忽略 ${targetAlerts.length} 个告警`)
    
    // 清空选择并刷新数据
    allSelectedAlerts.value = []
    selectedAlerts.value = []
    loadAlerts()
    loadStats()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to batch ignore:', error)
      ElMessage.error('批量忽略失败')
    }
  }
}

// 批量删除
const batchDelete = async () => {
  const targetAlerts = allSelectedAlerts.value.length > 0 ? allSelectedAlerts.value : selectedAlerts.value
  if (targetAlerts.length === 0) return

  console.log('批量删除 - 跨页面选择数量:', allSelectedAlerts.value.length)
  console.log('批量删除 - 当前页选择数量:', selectedAlerts.value.length)
  console.log('批量删除 - 实际处理数量:', targetAlerts.length)

  try {
    await ElMessageBox.confirm(
      `确认永久删除 ${targetAlerts.length} 个告警？此操作无法恢复！${allSelectedAlerts.value.length > 0 ? '（跨页面选择）' : '（当前页选择）'}`, 
      '批量删除', 
      {
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
        type: 'error',
        dangerouslyUseHTMLString: true
      }
    )

    // 使用批量删除API（性能优化）
    const alertIds = targetAlerts.map(alert => alert.id)
    
    console.log('准备删除的ID列表:', alertIds.slice(0, 10), '...共', alertIds.length, '个')
    
    // 分批删除，每批1000个，避免请求过大
    const batchSize = 1000
    let deletedCount = 0
    
    for (let i = 0; i < alertIds.length; i += batchSize) {
      const batchIds = alertIds.slice(i, i + batchSize)
      
      console.log(`正在删除第 ${i + 1} 到 ${i + batchIds.length} 个告警`)
      
      try {
        const response = await axios.post('/api/defense/ids/alerts/batch-delete', {
          alert_ids: batchIds
        })
        
        console.log('批量删除响应:', response.data)
        deletedCount += batchIds.length
        
        // 显示进度
        if (alertIds.length > batchSize) {
          ElMessage.info(`删除进度: ${deletedCount}/${alertIds.length}`)
        }
      } catch (err) {
        console.error('批量删除请求失败:', err.response?.data || err.message)
        throw err
      }
    }

    ElMessage.success({
      message: `已删除 ${deletedCount} 个告警，统计数据将在 5 秒内自动更新`,
      duration: 3000
    })
    
    // 清空选择并刷新数据
    allSelectedAlerts.value = []
    selectedAlerts.value = []
    loadAlerts()
    loadStats()
    
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to batch delete:', error)
      ElMessage.error('批量删除失败: ' + (error.response?.data?.error || error.message))
    }
  }
}

// 工具函数
const getAlertTypeText = (type) => {
  const typeMap = {
    port_scan: '端口扫描',
    dos: 'DoS 攻击',
    brute_force: '暴力破解',
    sql_injection: 'SQL 注入',
    xss: 'XSS 攻击'
  }
  return typeMap[type] || type
}

const getSeverityText = (severity) => {
  const severityMap = {
    low: '低',
    medium: '中',
    high: '高',
    critical: '严重'
  }
  return severityMap[severity] || severity
}

const getSeverityTagType = (severity) => {
  const typeMap = {
    low: 'info',
    medium: 'warning',
    high: 'danger',
    critical: 'danger'
  }
  return typeMap[severity] || 'info'
}

const getStatusText = (status) => {
  const statusMap = {
    new: '新告警',
    acknowledged: '已确认',
    resolved: '已解决',
    ignored: '已忽略'
  }
  return statusMap[status] || status
}

const getStatusTagType = (status) => {
  const typeMap = {
    new: 'danger',
    acknowledged: 'warning',
    resolved: 'success',
    ignored: 'info'
  }
  return typeMap[status] || 'info'
}

const formatTime = (time) => {
  if (!time) return '-'
  return new Date(time).toLocaleString('zh-CN')
}

const formatDetailKey = (key) => {
  const keyMap = {
    // 通用字段
    'packet_count': '数据包数量',
    'connection_count': '连接数量',
    'request_rate': '请求频率',
    'payload_size': '载荷大小',
    'pattern_matched': '匹配模式',
    'threshold_exceeded': '超过阈值',
    
    // DoS攻击相关
    'rate_per_sec': '每秒请求数',
    'request_count': '请求总数',
    'threshold': '阈值',
    'time_window': '时间窗口',
    
    // 端口扫描相关
    'ports_scanned': '扫描端口数',
    'scan_duration': '扫描持续时间',
    'scan_rate': '扫描速率',
    'port_range': '端口范围',
    
    // 暴力破解相关
    'failed_attempts': '失败尝试次数',
    'username': '用户名',
    'service': '服务类型',
    'attempt_rate': '尝试频率',
    
    // SQL注入相关
    'injection_type': '注入类型',
    'payload': '攻击载荷',
    'parameter': '参数',
    'query': '查询语句',
    
    // XSS相关
    'script_content': '脚本内容',
    'injection_point': '注入点',
    'encoding': '编码方式',
    
    // 网络相关
    'protocol': '协议',
    'source_ip': '源IP地址',
    'destination_ip': '目标IP地址',
    'source_port': '源端口',
    'destination_port': '目标端口',
    'bytes_transferred': '传输字节数',
    'duration': '持续时间'
  }
  return keyMap[key] || key
}

const formatDetailValue = (value) => {
  if (value === null || value === undefined || value === '') return '-'
  
  // 处理布尔值
  if (typeof value === 'boolean') {
    return value ? '是' : '否'
  }
  
  // 处理数组
  if (Array.isArray(value)) {
    return value.join(', ')
  }
  
  // 处理对象
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2)
  }
  
  // 处理数字
  if (typeof value === 'number') {
    return value.toString()
  }
  
  return String(value)
}

// 告警分析函数
const threatLevel = computed(() => {
  if (!currentAlert.value) return 0
  
  let score = 1
  
  // 基于攻击类型
  if (currentAlert.value.type === 'port_scan') {
    const portsScanned = getDetail('ports_scanned') || 0
    if (portsScanned > 100) score = 5
    else if (portsScanned > 50) score = 4
    else if (portsScanned > 20) score = 3
    else score = 2
  } else if (currentAlert.value.type === 'dos') {
    const requestCount = getDetail('request_count') || 0
    if (requestCount > 1000) score = 5
    else if (requestCount > 500) score = 4
    else if (requestCount > 200) score = 3
    else score = 2
  }
  
  // 基于严重程度调整
  if (currentAlert.value.severity === 'high') score = Math.min(score + 1, 5)
  if (currentAlert.value.severity === 'critical') score = 5
  
  return score
})

const getDetail = (key) => {
  return currentAlert.value?.details?.[key]
}

const getScanRate = () => {
  const portsScanned = getDetail('ports_scanned') || 0
  const timeWindow = getDetail('time_window') || '0s'
  const seconds = parseFloat(timeWindow.replace('s', '')) || 1
  return (portsScanned / seconds).toFixed(1)
}

const getScanPattern = () => {
  const portsScanned = getDetail('ports_scanned') || 0
  if (portsScanned > 100) return '大规模扫描'
  if (portsScanned > 50) return '中等规模扫描'
  if (portsScanned > 20) return '小规模扫描'
  return '探测性扫描'
}

const getCommonPorts = () => {
  // 模拟常见端口检测，实际应该从后端获取具体扫描的端口列表
  const commonPorts = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
  const portsScanned = getDetail('ports_scanned') || 0
  
  // 简单模拟：如果扫描端口数较多，假设包含一些常见端口
  if (portsScanned > 20) {
    return commonPorts.slice(0, Math.min(4, Math.floor(portsScanned / 15)))
  }
  return []
}

const getHighRiskPorts = () => {
  // 模拟高风险端口检测
  const highRiskPorts = [135, 139, 445, 1433, 3389, 5432]
  const portsScanned = getDetail('ports_scanned') || 0
  
  // 简单模拟：如果是大规模扫描，可能包含高风险端口
  if (portsScanned > 50) {
    return highRiskPorts.slice(0, Math.min(3, Math.floor(portsScanned / 25)))
  }
  return []
}

const getAttackIntensity = () => {
  const requestCount = getDetail('request_count') || 0
  const threshold = getDetail('threshold') || 100
  
  return Math.min(Math.round((requestCount / threshold) * 100), 100)
}

const getIntensityColor = (percentage) => {
  if (percentage >= 80) return '#f56c6c'
  if (percentage >= 60) return '#e6a23c'
  if (percentage >= 40) return '#409eff'
  return '#67c23a'
}

const getProtocolType = (protocol) => {
  if (!protocol) return 'info'
  const protocolLower = protocol.toLowerCase()
  if (['tcp', 'http', 'https'].includes(protocolLower)) return 'primary'
  if (['udp', 'dns'].includes(protocolLower)) return 'success'
  return 'warning'
}

const getResponseDelay = () => {
  if (!currentAlert.value?.timestamp || !currentAlert.value?.createdAt) return '未知'
  
  const attackTime = new Date(currentAlert.value.timestamp)
  const alertTime = new Date(currentAlert.value.createdAt)
  const delay = alertTime - attackTime
  
  if (delay < 1000) return '< 1秒'
  if (delay < 60000) return `${Math.round(delay / 1000)}秒`
  return `${Math.round(delay / 60000)}分钟`
}

const getRecommendations = () => {
  if (!currentAlert.value) return []
  
  const recommendations = []
  
  if (currentAlert.value.type === 'port_scan') {
    recommendations.push({
      type: 'firewall',
      level: 'warning',
      title: '防火墙配置建议',
      description: `建议在防火墙中阻断来源IP ${currentAlert.value.source} 的访问，防止进一步的攻击尝试。`
    })
    
    if (getHighRiskPorts().length > 0) {
      recommendations.push({
        type: 'security',
        level: 'error',
        title: '高危端口防护',
        description: '检测到对高风险端口的扫描，建议立即检查相关服务的安全配置，确保服务版本为最新且配置安全。'
      })
    }
    
    if (getDetail('ports_scanned') > 50) {
      recommendations.push({
        type: 'monitoring',
        level: 'warning',
        title: '加强监控',
        description: '大规模端口扫描可能是攻击的前奏，建议加强对该IP的监控，关注后续的攻击行为。'
      })
    }
  } else if (currentAlert.value.type === 'dos') {
    recommendations.push({
      type: 'rate_limit',
      level: 'error',
      title: '流量限制',
      description: `检测到DoS攻击，建议立即对来源IP ${currentAlert.value.source} 实施流量限制或临时阻断。`
    })
    
    if (getDetail('request_count') > 500) {
      recommendations.push({
        type: 'infrastructure',
        level: 'warning',
        title: '基础设施防护',
        description: '高强度DoS攻击，建议启用CDN、负载均衡等基础设施防护措施，提升系统抗攻击能力。'
      })
    }
  }
  
  // 通用建议
  recommendations.push({
    type: 'log',
    level: 'info',
    title: '日志保存',
    description: '建议保存相关日志记录，用于后续的安全分析和取证工作。'
  })
  
  return recommendations
}

// 生命周期
onMounted(() => {
  loadAlerts()
  loadStats()

  // 每30秒刷新一次
  refreshTimer = setInterval(() => {
    loadAlerts()
    loadStats()
  }, 30000)
})

onUnmounted(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
  }
})
</script>

<style scoped>
.ids-alerts {
  padding: 20px;
}

/* 告警详情页面样式 */
.alert-basic-info .card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.network-info {
  display: flex;
  align-items: center;
  gap: 8px;
}

.port-analysis {
  margin-top: 10px;
}

.port-list {
  margin-bottom: 15px;
}

.port-categories .el-descriptions {
  margin-top: 10px;
}

/* 统计卡片样式 */
.el-statistic {
  text-align: center;
}

.el-statistic .el-statistic__content {
  font-size: 24px;
  font-weight: bold;
}

/* 时间线样式 */
.alert-timeline .el-timeline {
  padding-left: 20px;
}

/* 建议措施样式 */
.alert-recommendations .el-alert {
  border-radius: 8px;
}

.alert-recommendations .el-alert:last-child {
  margin-bottom: 0;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .el-descriptions {
    --el-descriptions-item-bordered-label-background: #fafafa;
  }
  
  .el-row {
    margin: 0 !important;
  }
  
  .el-col {
    padding: 0 5px !important;
  }
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stat-card {
  height: 100px;
}

.stat-content {
  display: flex;
  align-items: center;
  height: 100%;
}

.stat-icon {
  font-size: 36px;
  margin-right: 15px;
}

.stat-text {
  flex: 1;
}

.stat-value {
  font-size: 24px;
  font-weight: bold;
  color: #303133;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-top: 5px;
}

:deep(.el-descriptions__label) {
  font-weight: 600;
}

:deep(.el-table) {
  font-size: 13px;
}
</style>
