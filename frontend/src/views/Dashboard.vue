<template>
  <div class="dashboard">
    <el-row :gutter="20">
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-content">
            <el-icon class="stat-icon" color="#409eff"><Monitor /></el-icon>
            <div class="stat-text">
              <div class="stat-value">{{ stats.activeSessions }}</div>
              <div class="stat-label">活动会话</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-content">
            <el-icon class="stat-icon" color="#67c23a"><DataLine /></el-icon>
            <div class="stat-text">
              <div class="stat-value">{{ formatNumber(stats.totalPackets) }}</div>
              <div class="stat-label">总数据包</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-content">
            <el-icon class="stat-icon" color="#e6a23c"><Warning /></el-icon>
            <div class="stat-text">
              <div class="stat-value">{{ stats.vulnerabilities }}</div>
              <div class="stat-label">发现漏洞</div>
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-content">
            <el-icon class="stat-icon" color="#f56c6c"><Lightning /></el-icon>
            <div class="stat-text">
              <div class="stat-value">{{ stats.attacks }}</div>
              <div class="stat-label">攻击测试</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>协议分布</span>
            </div>
          </template>
          <div style="height: 300px">
            <v-chart :option="protocolChartOption" autoresize />
          </div>
        </el-card>
      </el-col>

      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>流量趋势</span>
            </div>
          </template>
          <div style="height: 300px">
            <v-chart :option="trafficChartOption" autoresize />
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, LineChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent
} from 'echarts/components'
import wsClient from '@/utils/websocket'

use([
  CanvasRenderer,
  PieChart,
  LineChart,
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent
])

const stats = ref({
  activeSessions: 0,
  totalPackets: 0,
  vulnerabilities: 0,
  attacks: 0
})

const protocolChartOption = ref({
  tooltip: {
    trigger: 'item'
  },
  legend: {
    bottom: '5%',
    left: 'center'
  },
  series: [
    {
      name: '协议',
      type: 'pie',
      radius: ['40%', '70%'],
      avoidLabelOverlap: false,
      itemStyle: {
        borderRadius: 10,
        borderColor: '#fff',
        borderWidth: 2
      },
      label: {
        show: false,
        position: 'center'
      },
      emphasis: {
        label: {
          show: true,
          fontSize: 20,
          fontWeight: 'bold'
        }
      },
      labelLine: {
        show: false
      },
      data: []
    }
  ]
})

const trafficChartOption = ref({
  tooltip: {
    trigger: 'axis'
  },
  grid: {
    left: '3%',
    right: '4%',
    bottom: '3%',
    containLabel: true
  },
  xAxis: {
    type: 'category',
    boundaryGap: false,
    data: []
  },
  yAxis: {
    type: 'value'
  },
  series: [
    {
      name: '数据包数量',
      type: 'line',
      smooth: true,
      data: [],
      areaStyle: {
        color: 'rgba(64, 158, 255, 0.3)'
      }
    }
  ]
})

const formatNumber = (num) => {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')
}

// 加载总览统计
const loadOverviewStats = async () => {
  try {
    const res = await axios.get('/api/stats/overview')
    // 标准响应格式: {success: true, data: {...}}
    stats.value = res.data.data
  } catch (error) {
    console.error('Failed to load overview stats:', error)
  }
}

// 加载协议分布
const loadProtocolDistribution = async () => {
  try {
    const res = await axios.get('/api/stats/protocol-distribution')
    // 标准响应格式: {success: true, data: {protocols: [...]}}
    if (res.data.data.protocols && res.data.data.protocols.length > 0) {
      protocolChartOption.value.series[0].data = res.data.data.protocols
    }
  } catch (error) {
    console.error('Failed to load protocol distribution:', error)
  }
}

// 加载流量趋势
const loadTrafficTrend = async () => {
  try {
    const res = await axios.get('/api/stats/traffic-trend')
    // 标准响应格式: {success: true, data: {times: [...], counts: [...]}}
    if (res.data.data.times && res.data.data.counts) {
      trafficChartOption.value.xAxis.data = res.data.data.times
      trafficChartOption.value.series[0].data = res.data.data.counts
    }
  } catch (error) {
    console.error('Failed to load traffic trend:', error)
  }
}

// WebSocket 实时更新
const setupWebSocket = () => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const wsUrl = `${protocol}//${window.location.hostname}:${window.location.port}/api/ws`
  wsClient.connect(wsUrl)

  // 监听统计信息更新
  wsClient.on('stats', () => {
    // 有新的统计数据时刷新
    loadOverviewStats()
  })

  // 监听数据包事件
  wsClient.on('packet', () => {
    // 实时增加数据包计数
    stats.value.totalPackets++
  })
}

let refreshTimer = null

onMounted(() => {
  loadOverviewStats()
  loadProtocolDistribution()
  loadTrafficTrend()
  setupWebSocket()

  // 定时刷新数据
  refreshTimer = setInterval(() => {
    loadOverviewStats()
    loadProtocolDistribution()
    loadTrafficTrend()
  }, 30000) // 每30秒刷新一次
})

onUnmounted(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
  }
  wsClient.close()
})
</script>

<style scoped>
.dashboard {
  padding: 20px;
}

.stat-card {
  height: 120px;
}

.stat-content {
  display: flex;
  align-items: center;
  height: 100%;
}

.stat-icon {
  font-size: 48px;
  margin-right: 20px;
}

.stat-text {
  flex: 1;
}

.stat-value {
  font-size: 32px;
  font-weight: bold;
  color: #303133;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-top: 5px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
