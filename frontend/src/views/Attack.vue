<template>
  <div class="attack">
    <el-alert
      title="警告"
      type="warning"
      description="攻防模拟功能仅供授权测试使用，请勿用于非法用途。所有操作将被记录。"
      show-icon
      :closable="false"
      style="margin-bottom: 20px"
    />

    <el-tabs v-model="activeTab">
      <el-tab-pane label="数据包重放" name="replay">
        <el-card>
          <el-form :model="replayForm" label-width="120px">
            <el-form-item label="会话 ID">
              <el-input-number v-model="replayForm.sessionId" :min="1" />
            </el-form-item>

            <el-form-item label="网络接口">
              <el-input v-model="replayForm.interface" />
            </el-form-item>

            <el-form-item label="速度倍率">
              <el-slider v-model="replayForm.speedMultiplier" :min="0.1" :max="10" :step="0.1" />
              <span>{{ replayForm.speedMultiplier }}x</span>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="startReplay">开始重放</el-button>
            </el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="协议 Fuzzing" name="fuzzing">
        <el-card>
          <el-form :model="fuzzForm" label-width="120px">
            <el-form-item label="目标地址">
              <el-input v-model="fuzzForm.target" />
            </el-form-item>

            <el-form-item label="端口">
              <el-input-number v-model="fuzzForm.port" :min="1" :max="65535" />
            </el-form-item>

            <el-form-item label="协议">
              <el-select v-model="fuzzForm.protocol">
                <el-option label="TCP" value="TCP" />
                <el-option label="UDP" value="UDP" />
                <el-option label="HTTP" value="HTTP" />
                <el-option label="Modbus" value="Modbus" />
              </el-select>
            </el-form-item>

            <el-form-item label="迭代次数">
              <el-input-number v-model="fuzzForm.iterations" :min="1" :max="10000" />
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="startFuzzing">开始 Fuzzing</el-button>
            </el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'

const activeTab = ref('replay')

const replayForm = ref({
  sessionId: 1,
  interface: 'eth0',
  speedMultiplier: 1.0
})

const fuzzForm = ref({
  target: '',
  port: 502,
  protocol: 'Modbus',
  iterations: 100
})

const confirmAttack = async () => {
  try {
    await ElMessageBox.confirm(
      '此操作可能影响目标系统，确认已获得授权？',
      '确认',
      {
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
    return true
  } catch {
    return false
  }
}

const startReplay = async () => {
  if (!await confirmAttack()) return

  try {
    await axios.post('/api/attack/replay', {
      session_id: replayForm.value.sessionId,
      interface: replayForm.value.interface,
      speed_multiplier: replayForm.value.speedMultiplier,
      user_id: 'admin'
    })

    ElMessage.success('数据包重放已启动')
  } catch (error) {
    ElMessage.error('启动重放失败')
  }
}

const startFuzzing = async () => {
  if (!await confirmAttack()) return

  if (!fuzzForm.value.target) {
    ElMessage.warning('请输入目标地址')
    return
  }

  try {
    await axios.post('/api/attack/fuzz', {
      target: fuzzForm.value.target,
      port: fuzzForm.value.port,
      protocol: fuzzForm.value.protocol,
      iterations: fuzzForm.value.iterations,
      mutation_rate: 0.1,
      user_id: 'admin'
    })

    ElMessage.success('Fuzzing 已启动')
  } catch (error) {
    ElMessage.error('启动 Fuzzing 失败')
  }
}
</script>

<style scoped>
.attack {
  padding: 20px;
}
</style>
