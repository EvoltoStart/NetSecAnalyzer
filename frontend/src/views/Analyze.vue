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
import { ElMessage } from 'element-plus'
import axios from 'axios'

const protocols = ref([])
const loading = ref(false)

// 加载协议统计数据
const loadProtocols = async () => {
  loading.value = true
  try {
    const res = await axios.get('/api/stats/protocol-distribution')
    if (res.data.data) {
      // 计算总数
      const total = res.data.data.reduce((sum, item) => sum + item.value, 0)

      // 转换格式并计算百分比
      protocols.value = res.data.data.map(item => ({
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

const viewDetails = (protocol) => {
  ElMessage.info(`查看 ${protocol} 协议详情`)
}

onMounted(() => {
  loadProtocols()
  // 每30秒刷新一次
  setInterval(loadProtocols, 30000)
})
</script>

<style scoped>
.analyze {
  padding: 20px;
}
</style>
