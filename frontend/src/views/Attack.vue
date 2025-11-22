<template>
  <div class="attack">
    <el-alert
      title="⚠️ 安全警告"
      type="warning"
      description="攻防模拟功能仅供授权测试使用，请勿用于非法用途。所有操作将被记录并审计。"
      show-icon
      :closable="false"
      style="margin-bottom: 20px"
    />

    <el-tabs v-model="activeTab">
      <!-- 数据包重放 (攻击) -->
      <el-tab-pane name="replay">
        <template #label>
          <span><el-icon><VideoPlay /></el-icon> 数据包重放 (攻击)</span>
        </template>

        <el-row :gutter="20">
          <el-col :span="14">
            <el-card>
              <template #header>
                <div class="card-header">
                  <span>重放配置</span>
                  <el-button
                    v-if="replayForm.sessionId"
                    size="small"
                    @click="showPreview"
                    :icon="View"
                  >
                    预览数据包
                  </el-button>
                </div>
              </template>

              <el-form
                ref="replayFormRef"
                :model="replayForm"
                :rules="replayRules"
                label-width="120px"
              >
                <el-form-item label="选择会话" prop="sessionId">
                  <el-select
                    v-model="replayForm.sessionId"
                    placeholder="请选择会话"
                    style="width: 100%"
                    @change="onSessionChange"
                    filterable
                  >
                    <el-option
                      v-for="session in sessions"
                      :key="session.id"
                      :label="`${session.name} (${session.packetCount} 个数据包)`"
                      :value="session.id"
                    >
                      <div style="display: flex; justify-content: space-between">
                        <span>{{ session.name }}</span>
                        <span style="color: var(--el-text-color-secondary); font-size: 12px">
                          {{ session.packetCount }} 个数据包
                        </span>
                      </div>
                    </el-option>
                  </el-select>
                </el-form-item>

                <el-form-item label="数据包过滤" v-if="replayForm.sessionId">
                  <el-space wrap>
                    <el-select
                      v-model="replayForm.protocolFilter"
                      placeholder="协议过滤"
                      clearable
                      style="width: 150px"
                      @change="updateFilteredPacketCount"
                    >
                      <el-option label="全部协议" value="" />
                      <el-option label="TCP" value="TCP" />
                      <el-option label="UDP" value="UDP" />
                      <el-option label="HTTP" value="HTTP" />
                      <el-option label="DNS" value="DNS" />
                      <el-option label="Modbus" value="Modbus" />
                    </el-select>
                    <el-input
                      v-model="replayForm.srcAddrFilter"
                      placeholder="源地址过滤"
                      clearable
                      style="width: 180px"
                      @input="updateFilteredPacketCount"
                      @clear="updateFilteredPacketCount"
                    />
                    <el-input
                      v-model="replayForm.dstAddrFilter"
                      placeholder="目标地址过滤"
                      clearable
                      style="width: 180px"
                      @input="updateFilteredPacketCount"
                      @clear="updateFilteredPacketCount"
                    />
                  </el-space>
                  <div style="margin-top: 8px; font-size: 12px; color: var(--el-text-color-secondary)">
                    已选择: {{ filteredPacketCount }} / {{ totalPacketCount }} 个数据包
                  </div>
                </el-form-item>

                <el-form-item label="网络接口" prop="interface">
                  <el-select
                    v-model="replayForm.interface"
                    placeholder="请选择接口"
                    style="width: 100%"
                  >
                    <el-option
                      v-for="iface in interfaces"
                      :key="iface.name"
                      :label="`${iface.name} - ${iface.description}`"
                      :value="iface.name"
                    >
                      <div>
                        <div>{{ iface.name }}</div>
                        <div style="font-size: 12px; color: var(--el-text-color-secondary)">
                          {{ iface.description }}
                        </div>
                      </div>
                    </el-option>
                  </el-select>
                </el-form-item>

                <el-form-item label="速度倍率">
                  <el-slider
                    v-model="replayForm.speedMultiplier"
                    :min="0.1"
                    :max="10"
                    :step="0.1"
                    show-input
                    :marks="{ 0.5: '0.5x', 1: '1x', 2: '2x', 5: '5x', 10: '10x' }"
                  />
                  <div style="margin-top: 8px; font-size: 12px; color: var(--el-text-color-secondary)">
                    {{ replayForm.speedMultiplier }}x 速度
                    ({{ replayForm.speedMultiplier < 1 ? '慢速' : replayForm.speedMultiplier === 1 ? '正常' : '快速' }})
                  </div>
                </el-form-item>

                <el-form-item label="重放模式">
                  <el-radio-group v-model="replayForm.mode">
                    <el-radio label="once">单次重放</el-radio>
                    <el-radio label="loop">循环重放</el-radio>
                    <el-radio label="continuous">持续重放</el-radio>
                  </el-radio-group>
                </el-form-item>

                <el-form-item v-if="replayForm.mode === 'loop'" label="循环次数">
                  <el-input-number
                    v-model="replayForm.loopCount"
                    :min="1"
                    :max="1000"
                    style="width: 100%"
                  />
                </el-form-item>

                <el-form-item v-if="replayForm.mode === 'continuous'" label="持续时间">
                  <el-input-number
                    v-model="replayForm.duration"
                    :min="1"
                    :max="3600"
                    style="width: 100%"
                  />
                  <span style="margin-left: 10px">秒</span>
                </el-form-item>

                <el-form-item label="高级选项">
                  <el-checkbox v-model="replayForm.preserveTimestamp">保留原始时间戳</el-checkbox>
                  <el-checkbox v-model="replayForm.modifyChecksum">自动修正校验和</el-checkbox>
                </el-form-item>

                <el-form-item>
                  <el-button
                    type="primary"
                    @click="startReplay"
                    :loading="replayLoading"
                    :icon="VideoPlay"
                  >
                    开始重放
                  </el-button>
                  <el-button
                    @click="stopReplay"
                    :disabled="!currentReplayTask"
                    :icon="VideoPause"
                  >
                    停止重放
                  </el-button>
                  <el-button @click="resetReplayForm" :icon="RefreshRight">
                    重置
                  </el-button>
                </el-form-item>
              </el-form>
            </el-card>
          </el-col>

          <el-col :span="10">
            <el-card>
              <template #header>
                <div class="card-header">
                  <span>重放任务</span>
                  <el-button size="small" @click="loadTasks" :icon="Refresh">刷新</el-button>
                </div>
              </template>

              <el-table
                :data="replayTasks"
                stripe
                max-height="500"
                v-loading="tasksLoading"
              >
                <el-table-column prop="id" label="ID" width="60" />
                <el-table-column label="会话" min-width="120">
                  <template #default="{ row }">
                    {{ getSessionName(row) }}
                  </template>
                </el-table-column>
                <el-table-column prop="status" label="状态" width="90">
                  <template #default="{ row }">
                    <el-tag :type="getStatusType(row.status)" size="small">
                      {{ getStatusText(row.status) }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column prop="progress" label="进度" width="120">
                  <template #default="{ row }">
                    <el-progress
                      :percentage="row.progress"
                      :status="row.status === 'completed' ? 'success' : row.status === 'failed' ? 'exception' : undefined"
                    />
                  </template>
                </el-table-column>
                <el-table-column label="操作" width="80" fixed="right">
                  <template #default="{ row }">
                    <el-button
                      size="small"
                      @click="viewReplayResult(row)"
                      :icon="View"
                      link
                    >
                      详情
                    </el-button>
                  </template>
                </el-table-column>
              </el-table>

              <el-empty
                v-if="replayTasks.length === 0"
                description="暂无重放任务"
                :image-size="80"
              />
            </el-card>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- 协议 Fuzzing (攻击) -->
      <el-tab-pane name="fuzzing">
        <template #label>
          <span><el-icon><MagicStick /></el-icon> 协议 Fuzzing (攻击)</span>
        </template>

        <el-row :gutter="20">
          <el-col :span="14">
            <el-card>
              <template #header>
                <div class="card-header">
                  <span>Fuzzing 配置</span>
                  <el-tag type="info" size="small">智能模糊测试</el-tag>
                </div>
              </template>

              <el-form
                ref="fuzzFormRef"
                :model="fuzzForm"
                :rules="fuzzRules"
                label-width="120px"
              >
                <el-form-item label="目标地址" prop="target">
                  <el-input
                    v-model="fuzzForm.target"
                    placeholder="例如: 192.168.1.100 或 example.com"
                  >
                    <template #prepend>
                      <el-icon><Location /></el-icon>
                    </template>
                  </el-input>
                </el-form-item>

                <el-form-item label="端口" prop="port">
                  <el-input-number
                    v-model="fuzzForm.port"
                    :min="1"
                    :max="65535"
                    style="width: 100%"
                  />
                  <div style="margin-top: 8px; font-size: 12px; color: var(--el-text-color-secondary)">
                    常用端口: HTTP(80), HTTPS(443), Modbus(502), FTP(21)
                  </div>
                </el-form-item>

                <el-form-item label="协议" prop="protocol">
                  <el-select
                    v-model="fuzzForm.protocol"
                    style="width: 100%"
                    @change="onProtocolChange"
                  >
                    <el-option label="TCP" value="TCP">
                      <span>TCP</span>
                      <span style="float: right; color: var(--el-text-color-secondary); font-size: 12px">
                        传输控制协议
                      </span>
                    </el-option>
                    <el-option label="UDP" value="UDP">
                      <span>UDP</span>
                      <span style="float: right; color: var(--el-text-color-secondary); font-size: 12px">
                        用户数据报协议
                      </span>
                    </el-option>
                    <el-option label="HTTP" value="HTTP">
                      <span>HTTP</span>
                      <span style="float: right; color: var(--el-text-color-secondary); font-size: 12px">
                        超文本传输协议
                      </span>
                    </el-option>
                    <el-option label="Modbus" value="Modbus">
                      <span>Modbus</span>
                      <span style="float: right; color: var(--el-text-color-secondary); font-size: 12px">
                        工控协议
                      </span>
                    </el-option>
                    <el-option label="FTP" value="FTP">
                      <span>FTP</span>
                      <span style="float: right; color: var(--el-text-color-secondary); font-size: 12px">
                        文件传输协议
                      </span>
                    </el-option>
                  </el-select>
                </el-form-item>

                <el-form-item label="测试模板">
                  <el-select
                    v-model="fuzzForm.template"
                    placeholder="选择预设模板"
                    style="width: 100%"
                  >
                    <el-option
                      v-for="tpl in fuzzTemplates"
                      :key="tpl.name"
                      :label="tpl.name"
                      :value="tpl.value"
                    />
                  </el-select>
                  <el-button
                    style="margin-top: 10px"
                    size="small"
                    @click="showPayloadEditor = true"
                    :icon="Edit"
                  >
                    自定义 Payload
                  </el-button>
                </el-form-item>

                <el-form-item label="迭代次数">
                  <el-input-number
                    v-model="fuzzForm.iterations"
                    :min="1"
                    :max="10000"
                    style="width: 100%"
                  />
                  <div style="margin-top: 8px; font-size: 12px; color: var(--el-text-color-secondary)">
                    建议: 快速测试 100-500, 深度测试 1000-5000
                  </div>
                </el-form-item>

                <el-form-item label="变异策略">
                  <el-select v-model="fuzzForm.mutationStrategy" style="width: 100%">
                    <el-option label="随机变异" value="random" />
                    <el-option label="位翻转" value="bitflip" />
                    <el-option label="字节翻转" value="byteflip" />
                    <el-option label="边界值" value="boundary" />
                    <el-option label="智能变异" value="smart" />
                  </el-select>
                </el-form-item>

                <el-form-item label="变异率">
                  <el-slider
                    v-model="fuzzForm.mutationRate"
                    :min="0"
                    :max="1"
                    :step="0.01"
                    show-input
                    :marks="{ 0.1: '10%', 0.3: '30%', 0.5: '50%', 0.8: '80%', 1: '100%' }"
                  />
                </el-form-item>

                <el-form-item label="超时时间">
                  <el-input-number
                    v-model="fuzzForm.timeout"
                    :min="1"
                    :max="60"
                    style="width: 100%"
                  />
                  <span style="margin-left: 10px">秒</span>
                </el-form-item>

                <el-form-item label="并发数">
                  <el-input-number
                    v-model="fuzzForm.concurrency"
                    :min="1"
                    :max="100"
                    style="width: 100%"
                  />
                  <div style="margin-top: 8px; font-size: 12px; color: var(--el-text-color-secondary)">
                    并发请求数，建议不超过 10
                  </div>
                </el-form-item>

                <el-form-item label="异常检测">
                  <el-checkbox-group v-model="fuzzForm.anomalyDetection">
                    <el-checkbox label="timeout">超时检测</el-checkbox>
                    <el-checkbox label="error">错误响应</el-checkbox>
                    <el-checkbox label="crash">崩溃检测</el-checkbox>
                    <el-checkbox label="memory">内存异常</el-checkbox>
                  </el-checkbox-group>
                </el-form-item>

                <el-form-item>
                  <el-button
                    type="primary"
                    @click="startFuzzing"
                    :loading="fuzzLoading"
                    :icon="MagicStick"
                  >
                    开始 Fuzzing
                  </el-button>
                  <el-button
                    @click="stopFuzzing"
                    :disabled="!currentFuzzTask"
                    :icon="VideoPause"
                  >
                    停止 Fuzzing
                  </el-button>
                  <el-button @click="resetFuzzForm" :icon="RefreshRight">
                    重置
                  </el-button>
                </el-form-item>
              </el-form>
            </el-card>
          </el-col>

          <el-col :span="10">
            <el-card>
              <template #header>
                <div class="card-header">
                  <span>Fuzzing 任务</span>
                  <el-button size="small" @click="loadTasks" :icon="Refresh">刷新</el-button>
                </div>
              </template>

              <el-table
                :data="fuzzTasks"
                stripe
                max-height="500"
                v-loading="tasksLoading"
              >
                <el-table-column prop="id" label="ID" width="60" />
                <el-table-column label="目标" min-width="120">
                  <template #default="{ row }">
                    {{ getTargetDisplay(row) }}
                  </template>
                </el-table-column>
                <el-table-column prop="status" label="状态" width="90">
                  <template #default="{ row }">
                    <el-tag :type="getStatusType(row.status)" size="small">
                      {{ getStatusText(row.status) }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="异常" width="70">
                  <template #default="{ row }">
                    <el-tag v-if="getAnomalyCount(row) > 0" type="danger" size="small">
                      {{ getAnomalyCount(row) }}
                    </el-tag>
                    <span v-else style="color: var(--el-text-color-secondary)">0</span>
                  </template>
                </el-table-column>
                <el-table-column label="操作" width="80" fixed="right">
                  <template #default="{ row }">
                    <el-button
                      size="small"
                      @click="viewFuzzResult(row)"
                      :icon="View"
                      link
                    >
                      详情
                    </el-button>
                  </template>
                </el-table-column>
              </el-table>

              <el-empty
                v-if="fuzzTasks.length === 0"
                description="暂无 Fuzzing 任务"
                :image-size="80"
              />
            </el-card>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- 入侵检测 (防御) -->
      <el-tab-pane name="ids">
        <template #label>
          <span><el-icon><Lock /></el-icon> 入侵检测 (防御)</span>
        </template>

        <el-row :gutter="20">
          <el-col :span="14">
            <el-card>
              <template #header>
                <div class="card-header">
                  <span>IDS 配置</span>
                </div>
              </template>

              <el-form
                ref="idsFormRef"
                :model="idsForm"
                :rules="idsRules"
                label-width="120px"
              >
                <el-form-item label="监听接口" prop="interface">
                  <el-select v-model="idsForm.interface" placeholder="选择网络接口" style="width: 100%">
                    <el-option
                      v-for="iface in interfaces"
                      :key="iface.name"
                      :label="iface.name"
                      :value="iface.name"
                    >
                      <div>
                        <div>{{ iface.name }}</div>
                        <div style="font-size: 12px; color: var(--el-text-color-secondary)">
                          {{ iface.description }}
                        </div>
                      </div>
                    </el-option>
                  </el-select>
                </el-form-item>

                <el-form-item label="检测模式">
                  <el-radio-group v-model="idsForm.mode">
                    <el-radio label="signature">基于签名</el-radio>
                    <el-radio label="anomaly">基于异常</el-radio>
                    <el-radio label="hybrid">混合模式</el-radio>
                  </el-radio-group>
                </el-form-item>

                <el-form-item label="检测规则">
                  <el-checkbox-group v-model="idsForm.rules">
                    <el-checkbox label="port_scan">端口扫描</el-checkbox>
                    <el-checkbox label="dos">DoS 攻击</el-checkbox>
                    <el-checkbox label="brute_force">暴力破解</el-checkbox>
                    <el-checkbox label="sql_injection">SQL 注入</el-checkbox>
                    <el-checkbox label="xss">XSS 攻击</el-checkbox>
                  </el-checkbox-group>
                </el-form-item>

                <el-form-item label="敏感度">
                  <el-slider
                    v-model="idsForm.sensitivity"
                    :min="1"
                    :max="10"
                    :marks="{ 1: '低', 5: '中', 10: '高' }"
                    show-stops
                  />
                </el-form-item>

                <el-form-item label="告警阈值">
                  <el-input-number
                    v-model="idsForm.alertThreshold"
                    :min="1"
                    :max="100"
                    placeholder="触发告警的事件数"
                  />
                  <span style="margin-left: 10px; color: var(--el-text-color-secondary)">
                    次/分钟
                  </span>
                </el-form-item>

                <el-form-item label="自动阻断">
                  <el-switch v-model="idsForm.autoBlock" />
                  <span style="margin-left: 10px; color: var(--el-text-color-secondary)">
                    检测到攻击时自动阻断
                  </span>
                </el-form-item>

                <el-form-item>
                  <el-space>
                    <el-button
                      type="primary"
                      @click="startIDS"
                      :loading="idsLoading"
                      :disabled="currentIDSTask !== null"
                      :icon="VideoPlay"
                    >
                      启动检测
                    </el-button>
                    <el-button
                      type="warning"
                      @click="stopIDS"
                      :disabled="currentIDSTask === null"
                      :icon="VideoPause"
                    >
                      停止检测
                    </el-button>
                    <el-button @click="resetIDSForm" :icon="RefreshRight">
                      重置
                    </el-button>
                  </el-space>
                </el-form-item>
              </el-form>
            </el-card>
          </el-col>

          <el-col :span="10">
            <el-card>
              <template #header>
                <div class="card-header">
                  <span>检测状态</span>
                  <el-button size="small" @click="loadIDSTasks" :icon="Refresh">刷新</el-button>
                </div>
              </template>

              <div v-if="currentIDSTask">
                <el-descriptions :column="1" border size="small">
                  <el-descriptions-item label="状态">
                    <el-tag :type="getStatusType(currentIDSTask.status)">
                      {{ getStatusText(currentIDSTask.status) }}
                    </el-tag>
                  </el-descriptions-item>
                  <el-descriptions-item label="运行时间">
                    {{ formatDuration(currentIDSTask.createdAt) }}
                  </el-descriptions-item>
                  <el-descriptions-item label="检测事件">
                    <el-tag type="info">{{ currentIDSTask.eventsDetected || 0 }}</el-tag>
                  </el-descriptions-item>
                  <el-descriptions-item label="告警数">
                    <el-tag type="warning">{{ currentIDSTask.alertsCount || 0 }}</el-tag>
                  </el-descriptions-item>
                  <el-descriptions-item label="阻断数">
                    <el-tag type="danger">{{ currentIDSTask.blocksCount || 0 }}</el-tag>
                  </el-descriptions-item>
                </el-descriptions>

                <el-divider>
                  <span>最近告警</span>
                  <el-button
                    v-if="currentIDSTask && currentIDSTask.alertsCount > 0"
                    size="small"
                    type="primary"
                    link
                    @click="showAllAlerts"
                    style="margin-left: 10px"
                  >
                    查看全部 ({{ currentIDSTask.alertsCount }})
                  </el-button>
                </el-divider>

                <el-timeline v-if="getRecentAlerts(currentIDSTask).length > 0">
                  <el-timeline-item
                    v-for="(alert, index) in getRecentAlerts(currentIDSTask).slice(0, 5)"
                    :key="index"
                    :timestamp="formatTime(alert.timestamp)"
                    :type="getSeverityType(alert.severity)"
                  >
                    <strong>{{ getAlertTypeText(alert.type) }}</strong>: {{ alert.description }}
                    <br />
                    <span style="font-size: 12px; color: var(--el-text-color-secondary)">
                      来源: {{ alert.source }}
                    </span>
                  </el-timeline-item>
                </el-timeline>

                <el-empty v-else description="暂无告警" :image-size="80" />
              </div>

              <el-empty v-else description="未启动检测" :image-size="100" />
            </el-card>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- 任务历史 -->
      <el-tab-pane name="history">
        <template #label>
          <span><el-icon><Clock /></el-icon> 任务历史</span>
        </template>

        <el-card>
          <template #header>
            <div class="card-header">
              <span>所有任务</span>
              <el-space>
                <el-select
                  v-model="historyFilter.type"
                  placeholder="类型"
                  clearable
                  style="width: 120px"
                  size="small"
                >
                  <el-option label="全部" value="" />
                  <el-option label="数据包重放" value="replay" />
                  <el-option label="Fuzzing" value="fuzzing" />
                  <el-option label="入侵检测" value="ids" />
                </el-select>
                <el-select
                  v-model="historyFilter.status"
                  placeholder="状态"
                  clearable
                  style="width: 120px"
                  size="small"
                >
                  <el-option label="全部" value="" />
                  <el-option label="运行中" value="running" />
                  <el-option label="已完成" value="completed" />
                  <el-option label="已失败" value="failed" />
                  <el-option label="已停止" value="stopped" />
                </el-select>
                <el-button size="small" @click="loadTasks" :icon="Refresh">刷新</el-button>
                <el-button size="small" type="danger" @click="clearHistory" :icon="Delete">
                  清空历史
                </el-button>
              </el-space>
            </div>
          </template>

          <el-table
            :data="filteredTasks"
            stripe
            v-loading="tasksLoading"
          >
            <el-table-column prop="id" label="ID" width="70" />
            <el-table-column prop="type" label="类型" width="120">
              <template #default="{ row }">
                <el-tag 
                  :type="row.type === 'replay' ? 'primary' : row.type === 'fuzzing' ? 'success' : 'warning'" 
                  size="small"
                >
                  {{ row.type === 'replay' ? '数据包重放' : row.type === 'fuzzing' ? 'Fuzzing' : '入侵检测' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="目标" min-width="180">
              <template #default="{ row }">
                {{ row.type === 'replay' ? getSessionName(row) : row.type === 'ids' ? getIDSTarget(row) : getTargetDisplay(row) }}
              </template>
            </el-table-column>
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="getStatusType(row.status)" size="small">
                  {{ getStatusText(row.status) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="progress" label="进度" width="100">
              <template #default="{ row }">
                <el-progress
                  :percentage="row.progress"
                  :status="row.status === 'completed' ? 'success' : row.status === 'failed' ? 'exception' : undefined"
                  :show-text="false"
                />
              </template>
            </el-table-column>
            <el-table-column prop="createdAt" label="创建时间" width="160">
              <template #default="{ row }">
                {{ formatTime(row.createdAt) }}
              </template>
            </el-table-column>
            <el-table-column label="结果" min-width="150">
              <template #default="{ row }">
                <div v-if="row.type === 'replay' && row.result">
                  <span style="font-size: 12px">
                    发送: {{ row.result.packetsSent || 0 }}
                    <span v-if="row.result.packetsFailed" style="color: var(--el-color-danger)">
                      / 失败: {{ row.result.packetsFailed }}
                    </span>
                  </span>
                </div>
                <div v-else-if="row.type === 'fuzzing' && row.result">
                  <span style="font-size: 12px">
                    迭代: {{ row.result.iterations || 0 }}
                    <span v-if="row.result.anomalies > 0" style="color: var(--el-color-danger)">
                      / 异常: {{ row.result.anomalies }}
                    </span>
                  </span>
                </div>
                <span v-else style="color: var(--el-text-color-secondary)">-</span>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="150" fixed="right">
              <template #default="{ row }">
                <el-button
                  size="small"
                  @click="viewTaskDetail(row)"
                  :icon="View"
                  link
                >
                  详情
                </el-button>
                <el-button
                  size="small"
                  type="danger"
                  @click="deleteTask(row.id)"
                  :icon="Delete"
                  link
                  :disabled="row.status === 'running'"
                >
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>

          <el-empty
            v-if="filteredTasks.length === 0"
            description="暂无任务历史"
            :image-size="100"
          />
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <!-- 任务详情对话框 -->
    <el-dialog
      v-model="detailVisible"
      :title="`任务详情 #${currentTask?.id || ''}`"
      width="80%"
      destroy-on-close
    >
      <div v-if="currentTask">
        <el-descriptions :column="2" border size="default">
          <el-descriptions-item label="任务 ID">
            <el-tag>{{ currentTask.id }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="任务类型">
            <el-tag :type="currentTask.type === 'replay' ? 'primary' : currentTask.type === 'ids' ? 'warning' : 'success'">
              {{ currentTask.type === 'replay' ? '数据包重放' : currentTask.type === 'ids' ? '入侵检测' : 'Fuzzing' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="getStatusType(currentTask.status)">
              {{ getStatusText(currentTask.status) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="进度">
            <el-progress
              :percentage="currentTask.progress"
              :status="currentTask.status === 'completed' ? 'success' : currentTask.status === 'failed' ? 'exception' : undefined"
            />
          </el-descriptions-item>
          <el-descriptions-item label="创建时间">
            {{ formatTime(currentTask.createdAt) }}
          </el-descriptions-item>
          <el-descriptions-item label="完成时间">
            {{ currentTask.completedAt ? formatTime(currentTask.completedAt) : '未完成' }}
          </el-descriptions-item>
          <el-descriptions-item v-if="currentTask.type !== 'ids'" label="目标" :span="2">
            {{ currentTask.target }}
          </el-descriptions-item>
          <el-descriptions-item v-if="currentTask.type === 'ids'" label="监听接口" :span="2">
            {{ currentTask.interface || '-' }}
          </el-descriptions-item>
        </el-descriptions>

        <!-- Fuzzing 结果 -->
        <div v-if="currentTask.type === 'fuzzing' && currentTask.result">
          <el-divider>Fuzzing 结果</el-divider>

          <el-alert
            v-if="currentTask.result.anomalies > 0"
            :title="`⚠️ 发现 ${currentTask.result.anomalies} 个异常响应`"
            type="warning"
            style="margin-bottom: 15px"
            show-icon
          />

          <el-descriptions :column="3" border style="margin-bottom: 15px">
            <el-descriptions-item label="总迭代次数">
              {{ currentTask.result.iterations || 0 }}
            </el-descriptions-item>
            <el-descriptions-item label="异常数量">
              <el-tag v-if="currentTask.result.anomalies > 0" type="danger">
                {{ currentTask.result.anomalies }}
              </el-tag>
              <span v-else>0</span>
            </el-descriptions-item>
            <el-descriptions-item label="耗时">
              {{ currentTask.result.duration || 'N/A' }}
            </el-descriptions-item>
          </el-descriptions>

          <el-table
            v-if="currentTask.result.results"
            :data="currentTask.result.results"
            max-height="400"
            stripe
          >
            <el-table-column prop="iteration" label="迭代" width="80" />
            <el-table-column prop="response_time" label="响应时间" width="120">
              <template #default="{ row }">
                <span :style="{ color: row.response_time > 1000 ? 'var(--el-color-warning)' : '' }">
                  {{ row.response_time }}ms
                </span>
              </template>
            </el-table-column>
            <el-table-column prop="anomaly" label="异常" width="80">
              <template #default="{ row }">
                <el-tag v-if="row.anomaly" type="danger" size="small">是</el-tag>
                <span v-else style="color: var(--el-text-color-secondary)">否</span>
              </template>
            </el-table-column>
            <el-table-column prop="error" label="错误信息" min-width="200">
              <template #default="{ row }">
                <span v-if="row.error" style="color: var(--el-color-danger)">
                  {{ row.error }}
                </span>
                <span v-else style="color: var(--el-text-color-secondary)">-</span>
              </template>
            </el-table-column>
          </el-table>
        </div>

        <!-- 重放结果 -->
        <div v-else-if="currentTask.type === 'replay' && currentTask.result">
          <el-divider>重放结果</el-divider>

          <el-descriptions :column="2" border>
            <el-descriptions-item label="发送数据包">
              <el-tag type="success">{{ currentTask.result.packetsSent || 0 }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="失败数">
              <el-tag v-if="currentTask.result.packetsFailed > 0" type="danger">
                {{ currentTask.result.packetsFailed }}
              </el-tag>
              <span v-else>0</span>
            </el-descriptions-item>
            <el-descriptions-item label="速度倍率">
              {{ currentTask.result.speedMultiplier || currentTask.parameters?.speedMultiplier || 1 }}x
            </el-descriptions-item>
            <el-descriptions-item label="耗时">
              {{ currentTask.result.duration || 'N/A' }}
            </el-descriptions-item>
            <el-descriptions-item label="成功率" :span="2">
              <el-progress
                :percentage="calculateSuccessRate(currentTask.result)"
                :status="calculateSuccessRate(currentTask.result) === 100 ? 'success' : 'warning'"
              />
            </el-descriptions-item>
          </el-descriptions>
        </div>

        <!-- IDS 任务详情 -->
        <div v-else-if="currentTask.type === 'ids'">
          <el-divider>检测统计</el-divider>

          <el-descriptions :column="3" border style="margin-bottom: 15px">
            <el-descriptions-item label="检测事件">
              <el-tag type="info">{{ currentTask.eventsDetected || 0 }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="告警数量">
              <el-tag :type="currentTask.alertsCount > 0 ? 'warning' : 'success'">
                {{ currentTask.alertsCount || 0 }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="阻断次数">
              <el-tag :type="currentTask.blocksCount > 0 ? 'danger' : 'info'">
                {{ currentTask.blocksCount || 0 }}
              </el-tag>
            </el-descriptions-item>
          </el-descriptions>

          <el-divider>检测配置</el-divider>

          <el-descriptions :column="2" border>
            <el-descriptions-item label="检测模式">
              <el-tag>{{ currentTask.parameters?.mode === 'hybrid' ? '混合模式' : currentTask.parameters?.mode === 'signature' ? '签名模式' : '行为模式' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="自动阻断">
              <el-tag :type="currentTask.parameters?.auto_block ? 'danger' : 'info'">
                {{ currentTask.parameters?.auto_block ? '已启用' : '已禁用' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="敏感度">
              {{ currentTask.parameters?.sensitivity || 5 }}
            </el-descriptions-item>
            <el-descriptions-item label="告警阈值">
              {{ currentTask.parameters?.alert_threshold || 10 }}
            </el-descriptions-item>
            <el-descriptions-item label="检测规则" :span="2">
              <el-space wrap>
                <el-tag
                  v-for="rule in currentTask.parameters?.rules || []"
                  :key="rule"
                  size="small"
                  type="success"
                >
                  {{ formatRuleName(rule) }}
                </el-tag>
              </el-space>
            </el-descriptions-item>
          </el-descriptions>

          <!-- 最近告警 -->
          <div v-if="currentTask.recentAlerts && currentTask.recentAlerts.alerts && currentTask.recentAlerts.alerts.length > 0">
            <el-divider>最近告警</el-divider>
            <el-table
              :data="currentTask.recentAlerts.alerts.slice(0, 10)"
              max-height="300"
              stripe
              size="small"
            >
              <el-table-column prop="type" label="类型" width="120">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.severity === 'high' ? 'danger' : row.severity === 'medium' ? 'warning' : 'info'">
                    {{ formatRuleName(row.type) }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="source" label="源地址" width="140" />
              <el-table-column prop="destination" label="目标地址" width="140" />
              <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
              <el-table-column prop="timestamp" label="时间" width="160">
                <template #default="{ row }">
                  {{ formatTime(row.timestamp) }}
                </template>
              </el-table-column>
            </el-table>
          </div>
        </div>

        <!-- 参数详情（仅用于攻击任务） -->
        <div v-if="currentTask.type !== 'ids' && currentTask.parameters">
          <el-divider>任务参数</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item
              v-for="(value, key) in currentTask.parameters"
              :key="key"
              :label="formatParamKey(key)"
            >
              {{ formatParamValue(value) }}
            </el-descriptions-item>
          </el-descriptions>
        </div>
      </div>

      <template #footer>
        <el-button @click="detailVisible = false">关闭</el-button>
        <el-button
          v-if="currentTask?.status === 'running'"
          type="warning"
          @click="stopCurrentTask"
        >
          停止任务
        </el-button>
        <el-button
          v-if="currentTask?.status !== 'running'"
          type="danger"
          @click="deleteCurrentTask"
        >
          删除任务
        </el-button>
      </template>
    </el-dialog>

    <!-- 数据包预览对话框 -->
    <el-dialog
      v-model="previewVisible"
      title="数据包预览"
      width="70%"
      destroy-on-close
    >
      <el-table
        :data="previewPackets"
        stripe
        max-height="500"
        v-loading="previewLoading"
      >
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="protocol" label="协议" width="100">
          <template #default="{ row }">
            <el-tag size="small">{{ row.protocol }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="srcAddr" label="源地址" width="150" />
        <el-table-column prop="dstAddr" label="目标地址" width="150" />
        <el-table-column prop="length" label="长度" width="100">
          <template #default="{ row }">
            {{ row.length }} bytes
          </template>
        </el-table-column>
        <el-table-column prop="timestamp" label="时间戳" width="180">
          <template #default="{ row }">
            {{ formatTime(row.timestamp) }}
          </template>
        </el-table-column>
      </el-table>

      <template #footer>
        <el-button @click="previewVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <!-- Payload 编辑器对话框 -->
    <el-dialog
      v-model="showPayloadEditor"
      title="自定义 Payload 编辑器"
      width="60%"
      destroy-on-close
    >
      <el-form label-width="100px">
        <el-form-item label="编码格式">
          <el-radio-group v-model="payloadFormat">
            <el-radio label="text">文本</el-radio>
            <el-radio label="hex">十六进制</el-radio>
            <el-radio label="base64">Base64</el-radio>
          </el-radio-group>
        </el-form-item>

        <el-form-item label="Payload">
          <el-input
            v-model="customPayload"
            type="textarea"
            :rows="10"
            placeholder="输入自定义 payload..."
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="showPayloadEditor = false">取消</el-button>
        <el-button type="primary" @click="applyCustomPayload">应用</el-button>
      </template>
    </el-dialog>

    <!-- 全部告警弹窗 -->
    <el-dialog
      v-model="allAlertsVisible"
      title="全部告警"
      width="80%"
      :close-on-click-modal="false"
    >
      <div style="margin-bottom: 15px">
        <el-space wrap>
          <el-select v-model="alertFilter.type" placeholder="告警类型" clearable style="width: 150px" @change="loadAllAlerts">
            <el-option label="全部" value="" />
            <el-option label="端口扫描" value="port_scan" />
            <el-option label="DoS 攻击" value="dos" />
            <el-option label="暴力破解" value="brute_force" />
            <el-option label="SQL 注入" value="sql_injection" />
            <el-option label="XSS 攻击" value="xss" />
          </el-select>

          <el-select v-model="alertFilter.severity" placeholder="严重程度" clearable style="width: 120px" @change="loadAllAlerts">
            <el-option label="全部" value="" />
            <el-option label="低" value="low" />
            <el-option label="中" value="medium" />
            <el-option label="高" value="high" />
            <el-option label="严重" value="critical" />
          </el-select>

          <el-select v-model="alertFilter.status" placeholder="状态" clearable style="width: 120px" @change="loadAllAlerts">
            <el-option label="全部" value="" />
            <el-option label="新告警" value="new" />
            <el-option label="已确认" value="acknowledged" />
            <el-option label="已解决" value="resolved" />
            <el-option label="已忽略" value="ignored" />
          </el-select>

          <el-button type="primary" :icon="Refresh" @click="loadAllAlerts">刷新</el-button>
        </el-space>
      </div>

      <el-table :data="allAlerts" v-loading="alertsLoading" max-height="500">
        <el-table-column prop="id" label="ID" width="60" />
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
        <el-table-column prop="description" label="描述" min-width="200" />
        <el-table-column prop="source" label="来源" width="140" />
        <el-table-column prop="destination" label="目标" width="140" />
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="getStatusTagType(row.status)" size="small">
              {{ getStatusText2(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="timestamp" label="时间" width="160">
          <template #default="{ row }">
            {{ formatTime(row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="row.status === 'new'"
              size="small"
              type="primary"
              link
              @click="acknowledgeAlert(row)"
            >
              确认
            </el-button>
            <el-button
              v-if="row.status === 'acknowledged'"
              size="small"
              type="success"
              link
              @click="resolveAlert(row)"
            >
              解决
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <div style="margin-top: 15px; text-align: right">
        <el-pagination
          v-model:current-page="alertPagination.page"
          v-model:page-size="alertPagination.pageSize"
          :total="alertPagination.total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadAllAlerts"
          @size-change="loadAllAlerts"
        />
      </div>

      <template #footer>
        <el-button @click="allAlertsVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  VideoPlay, VideoPause, View, Refresh, Delete, Clock,
  MagicStick, RefreshRight, Edit, Location, Lock
} from '@element-plus/icons-vue'
import axios from 'axios'

const activeTab = ref('replay')

// 会话和接口列表
const sessions = ref([])
const interfaces = ref([])

// 重放表单
const replayForm = ref({
  sessionId: null,
  interface: '',
  speedMultiplier: 1.0,
  mode: 'once',
  loopCount: 1,
  duration: 60,
  protocolFilter: '',
  srcAddrFilter: '',
  dstAddrFilter: '',
  preserveTimestamp: false,
  modifyChecksum: true
})

const replayFormRef = ref(null)
const replayRules = {
  sessionId: [{ required: true, message: '请选择会话', trigger: 'change' }],
  interface: [{ required: true, message: '请选择网络接口', trigger: 'change' }]
}

// Fuzzing 表单
const fuzzForm = ref({
  target: '',
  port: 502,
  protocol: 'Modbus',
  template: '',
  iterations: 100,
  mutationRate: 0.3,
  mutationStrategy: 'smart',
  timeout: 5,
  concurrency: 1,
  anomalyDetection: ['timeout', 'error', 'crash']
})

const fuzzFormRef = ref(null)
const fuzzRules = {
  target: [{ required: true, message: '请输入目标地址', trigger: 'blur' }],
  port: [{ required: true, message: '请输入端口', trigger: 'blur' }],
  protocol: [{ required: true, message: '请选择协议', trigger: 'change' }]
}

// Fuzzing 模板
const fuzzTemplates = ref([])

// IDS 表单
const idsForm = ref({
  interface: '',
  mode: 'hybrid',
  rules: ['port_scan', 'dos', 'brute_force', 'sql_injection', 'xss'],  // 默认选择所有规则
  sensitivity: 5,
  alertThreshold: 10,
  autoBlock: false
})

const idsFormRef = ref(null)
const idsRules = {
  interface: [{ required: true, message: '请选择网络接口', trigger: 'change' }]
}

// 任务列表
const replayTasks = ref([])
const fuzzTasks = ref([])
const idsTasks = ref([])
const allTasks = ref([])

// 当前任务
const currentReplayTask = ref(null)
const currentFuzzTask = ref(null)
const currentIDSTask = ref(null)
const currentTask = ref(null)

// 加载状态
const replayLoading = ref(false)
const fuzzLoading = ref(false)
const idsLoading = ref(false)
const tasksLoading = ref(false)
const detailVisible = ref(false)
const previewVisible = ref(false)
const previewLoading = ref(false)
const showPayloadEditor = ref(false)

// 告警管理
const allAlertsVisible = ref(false)
const allAlerts = ref([])
const alertsLoading = ref(false)
const alertFilter = ref({
  type: '',
  severity: '',
  status: ''
})
const alertPagination = ref({
  page: 1,
  pageSize: 20,
  total: 0
})

// 预览数据
const previewPackets = ref([])
const totalPacketCount = ref(0)
const filteredPacketCount = ref(0)

// Payload 编辑器
const payloadFormat = ref('text')
const customPayload = ref('')

// 历史过滤
const historyFilter = ref({
  type: '',
  status: ''
})

// 计算属性：过滤后的任务列表
const filteredTasks = computed(() => {
  let tasks = allTasks.value

  if (historyFilter.value.type) {
    tasks = tasks.filter(t => t.type === historyFilter.value.type)
  }

  if (historyFilter.value.status) {
    tasks = tasks.filter(t => t.status === historyFilter.value.status)
  }

  return tasks
})

// 定时器
let refreshTimer = null

// 加载会话列表
const loadSessions = async () => {
  try {
    const res = await axios.get('/api/capture/sessions')
    sessions.value = res.data.data.sessions || []
  } catch (error) {
    console.error('加载会话列表失败:', error)
  }
}

// 加载网络接口
const loadInterfaces = async () => {
  try {
    const res = await axios.get('/api/capture/interfaces')
    interfaces.value = res.data.data.interfaces || []
    
    // 只在没有保存的配置时，才设置默认值
    if (interfaces.value.length > 0 && !replayForm.value.interface) {
      replayForm.value.interface = interfaces.value[0].name
    }
    
    // 验证已保存的接口是否仍然存在
    if (replayForm.value.interface) {
      const exists = interfaces.value.some(i => i.name === replayForm.value.interface)
      if (!exists && interfaces.value.length > 0) {
        // 如果保存的接口不存在了，则使用第一个
        replayForm.value.interface = interfaces.value[0].name
        saveReplayConfig()
      }
    }
  } catch (error) {
    console.error('加载网络接口失败:', error)
  }
}

// 加载任务列表
const loadTasks = async () => {
  tasksLoading.value = true
  try {
    // 并行加载攻击任务和IDS任务
    const [attackRes, idsRes] = await Promise.all([
      axios.get('/api/attack/tasks'),
      axios.get('/api/defense/ids/tasks')
    ])
    
    // 攻击任务
    const attackTasks = attackRes.data.data.tasks || []
    // IDS任务
    const idsTaskList = idsRes.data.data.tasks || []
    
    // 合并所有任务并按创建时间倒序排序（最新的在前）
    allTasks.value = [...attackTasks, ...idsTaskList].sort((a, b) => {
      return new Date(b.createdAt) - new Date(a.createdAt)
    })
    replayTasks.value = attackTasks.filter(t => t.type === 'replay')
    fuzzTasks.value = attackTasks.filter(t => t.type === 'fuzzing')
    // 更新IDS任务列表
    idsTasks.value = idsTaskList

    // 更新当前任务
    const runningReplay = replayTasks.value.find(t => t.status === 'running')
    const runningFuzz = fuzzTasks.value.find(t => t.status === 'running')
    currentReplayTask.value = runningReplay || null
    currentFuzzTask.value = runningFuzz || null
  } catch (error) {
    console.error('加载任务列表失败:', error)
    ElMessage.error('加载任务列表失败')
  } finally {
    tasksLoading.value = false
  }
}

// 会话改变时
const onSessionChange = async () => {
  if (!replayForm.value.sessionId) return

  // 加载会话的数据包统计
  try {
    const res = await axios.get(`/api/capture/sessions/${replayForm.value.sessionId}/packets`, {
      params: { page: 1, page_size: 1 }
    })
    // 标准响应格式: {success: true, data: {packets: [...]}, meta: {total: ...}}
    totalPacketCount.value = res.data.meta?.total || 0
    filteredPacketCount.value = res.data.meta?.total || 0
  } catch (error) {
    console.error('加载数据包统计失败:', error)
  }
}

// 更新过滤后的数据包数量
const updateFilteredPacketCount = async () => {
  if (!replayForm.value.sessionId) return

  try {
    const params = {
      page: 1,
      page_size: 1
    }

    if (replayForm.value.protocolFilter) params.protocol = replayForm.value.protocolFilter
    if (replayForm.value.srcAddrFilter) params.src_addr = replayForm.value.srcAddrFilter
    if (replayForm.value.dstAddrFilter) params.dst_addr = replayForm.value.dstAddrFilter

    const res = await axios.get(`/api/capture/sessions/${replayForm.value.sessionId}/packets`, { params })
    filteredPacketCount.value = res.data.meta?.total || 0
  } catch (error) {
    console.error('更新过滤数据包数量失败:', error)
  }
}

// 预览数据包
const showPreview = async () => {
  if (!replayForm.value.sessionId) return

  previewVisible.value = true
  previewLoading.value = true

  try {
    const params = {
      page: 1,
      page_size: 100
    }

    if (replayForm.value.protocolFilter) params.protocol = replayForm.value.protocolFilter
    if (replayForm.value.srcAddrFilter) params.src_addr = replayForm.value.srcAddrFilter
    if (replayForm.value.dstAddrFilter) params.dst_addr = replayForm.value.dstAddrFilter

    const res = await axios.get(`/api/capture/sessions/${replayForm.value.sessionId}/packets`, { params })
    // 标准响应格式: {success: true, data: {packets: [...]}, meta: {total: ...}}
    previewPackets.value = res.data.data.packets || []
    filteredPacketCount.value = res.data.meta?.total || 0
  } catch (error) {
    ElMessage.error('加载数据包失败')
  } finally {
    previewLoading.value = false
  }
}

// 协议改变时更新模板
const onProtocolChange = () => {
  // 清空当前模板，让loadFuzzTemplates设置新的默认模板
  fuzzForm.value.template = ''
  loadFuzzTemplates()
}

// 加载 Fuzzing 模板
const loadFuzzTemplates = () => {
  const protocol = fuzzForm.value.protocol
  const templates = {
    'HTTP': [
      { name: 'GET 请求', value: 'GET / HTTP/1.1\r\nHost: target\r\n\r\n' },
      { name: 'POST 请求', value: 'POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n' },
      { name: 'PUT 请求', value: 'PUT / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n' },
      { name: 'DELETE 请求', value: 'DELETE / HTTP/1.1\r\nHost: target\r\n\r\n' },
      { name: 'SQL注入测试', value: 'GET /login?user=admin\' OR \'1\'=\'1&pass=test HTTP/1.1\r\nHost: target\r\n\r\n' },
      { name: 'XSS测试', value: 'GET /search?q=<scr' + 'ipt>alert(1)</scr' + 'ipt> HTTP/1.1\r\nHost: target\r\n\r\n' },
      { name: '路径遍历', value: 'GET /../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n' },
      { name: '命令注入', value: 'GET /cmd?exec=ls;cat /etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n' }
    ],
    'Modbus': [
      { name: '读取保持寄存器', value: '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A' },
      { name: '读取输入寄存器', value: '\x00\x01\x00\x00\x00\x06\x01\x04\x00\x00\x00\x0A' },
      { name: '写单个寄存器', value: '\x00\x01\x00\x00\x00\x06\x01\x06\x00\x00\x00\x03' },
      { name: '读取线圈', value: '\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x10' },
      { name: '写多个寄存器', value: '\x00\x01\x00\x00\x00\x0B\x01\x10\x00\x00\x00\x02\x04\x00\x0A\x01\x02' },
      { name: '读取设备标识', value: '\x00\x01\x00\x00\x00\x05\x01\x2B\x0E\x01\x00' },
      { name: '诊断功能', value: '\x00\x01\x00\x00\x00\x04\x01\x08\x00\x00' },
      { name: '无效功能码', value: '\x00\x01\x00\x00\x00\x06\x01\xFF\x00\x00\x00\x0A' }
    ],
    'FTP': [
      { name: 'USER 命令', value: 'USER anonymous\r\n' },
      { name: 'PASS 命令', value: 'PASS guest\r\n' },
      { name: 'LIST 命令', value: 'LIST\r\n' },
      { name: 'RETR 命令', value: 'RETR file.txt\r\n' },
      { name: 'STOR 命令', value: 'STOR upload.txt\r\n' },
      { name: 'CWD 路径遍历', value: 'CWD ../../../../etc\r\n' },
      { name: 'MKD 创建目录', value: 'MKD testdir\r\n' },
      { name: 'DELE 删除文件', value: 'DELE file.txt\r\n' }
    ],
    'TCP': [
      { name: '简单文本', value: 'Hello World' },
      { name: '格式化字符串', value: 'test %s %x %n %p' },
      { name: 'SQL注入', value: 'admin\' OR \'1\'=\'1\' --' },
      { name: '命令注入', value: 'test; ls -la | cat /etc/passwd' },
      { name: 'XSS攻击', value: '<scr' + 'ipt>alert(document.cookie)</scr' + 'ipt>' },
      { name: '路径遍历', value: '../../../etc/passwd' },
      { name: 'LDAP注入', value: 'admin)(|(password=*))' },
      { name: 'XXE注入', value: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' },
      { name: '缓冲区溢出', value: 'A'.repeat(500) },
      { name: '二进制数据', value: '\x00\x01\x02\x03\x04\x05' },
      { name: 'NULL字节注入', value: 'test\x00admin' },
      { name: '整数溢出', value: '\xFF\xFF\xFF\xFF' },
      { name: '自定义 TCP', value: '' }
    ],
    'UDP': [
      { name: 'DNS 查询', value: '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' },
      { name: 'DNS 放大攻击', value: '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x03\x77\x77\x77\x07\x65\x78\x61\x6D\x70\x6C\x65\x03\x63\x6F\x6D\x00\x00\xFF\x00\x01' },
      { name: 'SNMP GET', value: '\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63' },
      { name: 'SNMP SET', value: '\x30\x39\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xA3\x2C' },
      { name: 'NTP 请求', value: '\x1B\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' },
      { name: 'TFTP 读取', value: '\x00\x01config.txt\x00octet\x00' },
      { name: 'SIP INVITE', value: 'INVITE sip:user@target SIP/2.0\r\n' },
      { name: '简单文本', value: 'UDP Test Data' },
      { name: '自定义 UDP', value: '' }
    ]
  }

  fuzzTemplates.value = templates[protocol] || []
  
  // 如果有模板且当前template为空，则设置第一个模板
  if (fuzzTemplates.value.length > 0 && !fuzzForm.value.template) {
    fuzzForm.value.template = fuzzTemplates.value[0].value
  }
}

// 确认攻击操作
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

// 开始重放
const startReplay = async () => {
  // 表单验证
  if (!replayFormRef.value) return

  try {
    await replayFormRef.value.validate()
  } catch {
    return
  }

  if (!await confirmAttack()) return

  // 保存配置到 localStorage
  saveReplayConfig()

  replayLoading.value = true
  try {
    const payload = {
      session_id: replayForm.value.sessionId,
      interface: replayForm.value.interface,
      speed_multiplier: replayForm.value.speedMultiplier,
      mode: replayForm.value.mode,
      loop_count: replayForm.value.loopCount,
      duration: replayForm.value.duration,
      protocol_filter: replayForm.value.protocolFilter,
      src_addr_filter: replayForm.value.srcAddrFilter,
      dst_addr_filter: replayForm.value.dstAddrFilter,
      preserve_timestamp: replayForm.value.preserveTimestamp,
      modify_checksum: replayForm.value.modifyChecksum,
      user_id: 'admin'
    }

    const res = await axios.post('/api/attack/replay', payload)

    ElMessage.success('数据包重放已启动')
    currentReplayTask.value = res.data.data
    await loadTasks()
  } catch (error) {
    ElMessage.error('启动重放失败: ' + (error.response?.data?.error || error.message))
  } finally {
    replayLoading.value = false
  }
}

// 重置重放表单
const resetReplayForm = () => {
  if (replayFormRef.value) {
    replayFormRef.value.resetFields()
  }
  replayForm.value = {
    sessionId: null,
    interface: interfaces.value.length > 0 ? interfaces.value[0].name : '',
    speedMultiplier: 1.0,
    mode: 'once',
    loopCount: 1,
    duration: 60,
    protocolFilter: '',
    srcAddrFilter: '',
    dstAddrFilter: '',
    preserveTimestamp: false,
    modifyChecksum: true
  }
  totalPacketCount.value = 0
  filteredPacketCount.value = 0
}

// 停止重放
const stopReplay = async () => {
  if (!currentReplayTask.value) return

  try {
    await axios.post(`/api/attack/tasks/${currentReplayTask.value.id}/stop`)
    ElMessage.success('已停止重放')
    currentReplayTask.value = null
    await loadTasks()
  } catch (error) {
    ElMessage.error('停止失败: ' + (error.response?.data?.error || error.message))
  }
}

// 开始 Fuzzing
const startFuzzing = async () => {
  // 表单验证
  if (!fuzzFormRef.value) return

  try {
    await fuzzFormRef.value.validate()
  } catch {
    return
  }

  if (!await confirmAttack()) return

  // 保存配置到 localStorage
  saveFuzzConfig()

  fuzzLoading.value = true
  try {
    const payload = {
      target: fuzzForm.value.target,
      port: fuzzForm.value.port,
      protocol: fuzzForm.value.protocol,
      template: fuzzForm.value.template,
      iterations: fuzzForm.value.iterations,
      mutation_rate: fuzzForm.value.mutationRate,
      mutation_strategy: fuzzForm.value.mutationStrategy,
      timeout: fuzzForm.value.timeout,
      concurrency: fuzzForm.value.concurrency,
      anomaly_detection: fuzzForm.value.anomalyDetection,
      user_id: 'admin'
    }

    const res = await axios.post('/api/attack/fuzz', payload)

    ElMessage.success('Fuzzing 已启动')
    currentFuzzTask.value = res.data.data
    await loadTasks()
  } catch (error) {
    ElMessage.error('启动 Fuzzing 失败: ' + (error.response?.data?.error || error.message))
  } finally {
    fuzzLoading.value = false
  }
}

// 重置 Fuzzing 表单
const resetFuzzForm = () => {
  if (fuzzFormRef.value) {
    fuzzFormRef.value.resetFields()
  }
  fuzzForm.value = {
    target: '',
    port: 502,
    protocol: 'Modbus',
    template: '',
    iterations: 100,
    mutationRate: 0.3,
    mutationStrategy: 'smart',
    timeout: 5,
    concurrency: 1,
    anomalyDetection: ['timeout', 'error', 'crash']
  }
  loadFuzzTemplates()
}

// 应用自定义 Payload
const applyCustomPayload = () => {
  if (!customPayload.value) {
    ElMessage.warning('请输入 Payload')
    return
  }

  fuzzForm.value.template = customPayload.value
  showPayloadEditor.value = false
  ElMessage.success('Payload 已应用')
}

// 启动 IDS
const startIDS = async () => {
  // 表单验证
  if (!idsFormRef.value) return

  try {
    await idsFormRef.value.validate()
  } catch {
    return
  }

  // 保存配置到 localStorage
  saveIDSConfig()

  idsLoading.value = true
  try {
    const payload = {
      interface: idsForm.value.interface,
      mode: idsForm.value.mode,
      rules: idsForm.value.rules,
      sensitivity: idsForm.value.sensitivity,
      alert_threshold: idsForm.value.alertThreshold,
      auto_block: idsForm.value.autoBlock,
      user_id: 'admin'
    }

    const res = await axios.post('/api/defense/ids/start', payload)

    ElMessage.success('入侵检测已启动')
    // 修复：正确获取 task 对象
    currentIDSTask.value = res.data.data.task
    await loadIDSTasks()
  } catch (error) {
    ElMessage.error('启动 IDS 失败: ' + (error.response?.data?.error || error.message))
  } finally {
    idsLoading.value = false
  }
}

// 停止 IDS
const stopIDS = async () => {
  if (!currentIDSTask.value) return

  try {
    await axios.post(`/api/defense/ids/${currentIDSTask.value.id}/stop`)
    ElMessage.success('入侵检测已停止')
    currentIDSTask.value = null
    await loadIDSTasks()
  } catch (error) {
    ElMessage.error('停止 IDS 失败: ' + (error.response?.data?.error || error.message))
  }
}

// 加载 IDS 任务
const loadIDSTasks = async () => {
  try {
    const res = await axios.get('/api/defense/ids/tasks')
    // 标准响应格式: {success: true, data: {tasks: [...]}, meta: {...}}
    idsTasks.value = res.data.data.tasks || []

    // 修复：如果当前有任务，更新它的数据；否则查找运行中的任务
    if (currentIDSTask.value) {
      // 更新当前任务的数据
      const updated = idsTasks.value.find(t => t.id === currentIDSTask.value.id)
      if (updated) {
        currentIDSTask.value = updated
      } else {
        // 任务不存在了，清空
        currentIDSTask.value = null
      }
    } else {
      // 没有当前任务，查找运行中的任务
      const running = idsTasks.value.find(t => t.status === 'running')
      currentIDSTask.value = running || null
    }
  } catch (error) {
    console.error('加载 IDS 任务失败:', error)
  }
}

// 重置 IDS 表单
const resetIDSForm = () => {
  if (idsFormRef.value) {
    idsFormRef.value.resetFields()
  }
  idsForm.value = {
    interface: interfaces.value.length > 0 ? interfaces.value[0].name : '',
    mode: 'hybrid',
    rules: ['port_scan', 'dos', 'brute_force'],
    sensitivity: 5,
    alertThreshold: 10,
    autoBlock: false
  }
}

// 格式化持续时间
const formatDuration = (startTime) => {
  if (!startTime) return 'N/A'
  const start = new Date(startTime)
  const now = new Date()
  const diff = Math.floor((now - start) / 1000) // 秒

  const hours = Math.floor(diff / 3600)
  const minutes = Math.floor((diff % 3600) / 60)
  const seconds = diff % 60

  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`
  } else if (minutes > 0) {
    return `${minutes}m ${seconds}s`
  } else {
    return `${seconds}s`
  }
}

// 获取最近告警列表
const getRecentAlerts = (task) => {
  if (!task || !task.recentAlerts) return []

  // 后端返回的格式是 {alerts: [...]}
  if (task.recentAlerts.alerts && Array.isArray(task.recentAlerts.alerts)) {
    return task.recentAlerts.alerts
  }

  // 兼容直接是数组的情况
  if (Array.isArray(task.recentAlerts)) {
    return task.recentAlerts
  }

  return []
}

// 显示全部告警
const showAllAlerts = () => {
  allAlertsVisible.value = true
  loadAllAlerts()
}

// 加载全部告警
const loadAllAlerts = async () => {
  if (!currentIDSTask.value) return

  alertsLoading.value = true
  try {
    const params = {
      task_id: currentIDSTask.value.id,
      page: alertPagination.value.page,
      page_size: alertPagination.value.pageSize
    }

    if (alertFilter.value.type) params.type = alertFilter.value.type
    if (alertFilter.value.severity) params.severity = alertFilter.value.severity
    if (alertFilter.value.status) params.status = alertFilter.value.status

    const res = await axios.get('/api/defense/ids/alerts', { params })
    allAlerts.value = res.data.data.alerts || []
    alertPagination.value.total = res.data.meta.total || 0
  } catch (error) {
    console.error('Failed to load alerts:', error)
    ElMessage.error('加载告警失败')
  } finally {
    alertsLoading.value = false
  }
}

// 确认告警
const acknowledgeAlert = async (alert) => {
  try {
    await axios.put(`/api/defense/ids/alerts/${alert.id}`, {
      status: 'acknowledged',
      acknowledgedBy: 'admin'
    })
    ElMessage.success('告警已确认')
    loadAllAlerts()
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
    loadAllAlerts()
  } catch (error) {
    console.error('Failed to resolve alert:', error)
    ElMessage.error('解决告警失败')
  }
}

// 获取告警类型文本
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

// 获取严重程度文本
const getSeverityText = (severity) => {
  const severityMap = {
    low: '低',
    medium: '中',
    high: '高',
    critical: '严重'
  }
  return severityMap[severity] || severity
}

// 获取严重程度标签类型
const getSeverityTagType = (severity) => {
  const typeMap = {
    low: 'info',
    medium: 'warning',
    high: 'danger',
    critical: 'danger'
  }
  return typeMap[severity] || 'info'
}

// 获取严重程度时间线类型
const getSeverityType = (severity) => {
  const typeMap = {
    low: 'info',
    medium: 'warning',
    high: 'danger',
    critical: 'danger'
  }
  return typeMap[severity] || 'info'
}

// 获取状态文本
const getStatusText2 = (status) => {
  const statusMap = {
    new: '新告警',
    acknowledged: '已确认',
    resolved: '已解决',
    ignored: '已忽略'
  }
  return statusMap[status] || status
}

// 获取状态标签类型
const getStatusTagType = (status) => {
  const typeMap = {
    new: 'danger',
    acknowledged: 'warning',
    resolved: 'success',
    ignored: 'info'
  }
  return typeMap[status] || 'info'
}

// 停止 Fuzzing
const stopFuzzing = async () => {
  if (!currentFuzzTask.value) return

  try {
    await axios.post(`/api/attack/tasks/${currentFuzzTask.value.id}/stop`)
    ElMessage.success('已停止 Fuzzing')
    currentFuzzTask.value = null
    await loadTasks()
  } catch (error) {
    ElMessage.error('停止失败: ' + (error.response?.data?.error || error.message))
  }
}

// 查看重放结果
const viewReplayResult = (task) => {
  currentTask.value = task
  detailVisible.value = true
}

// 查看 Fuzzing 结果
const viewFuzzResult = (task) => {
  currentTask.value = task
  detailVisible.value = true
}

// 查看任务详情
const viewTaskDetail = (task) => {
  currentTask.value = task
  detailVisible.value = true
}

// 删除任务
const deleteTask = async (taskId) => {
  try {
    // 找到任务类型
    const task = allTasks.value.find(t => t.id === taskId)
    if (!task) {
      ElMessage.error('任务不存在')
      return
    }

    await ElMessageBox.confirm('确认删除此任务？删除后无法恢复。', '确认删除', {
      confirmButtonText: '确认',
      cancelButtonText: '取消',
      type: 'warning'
    })

    // 根据任务类型调用不同的API
    if (task.type === 'ids') {
      await axios.delete(`/api/defense/ids/tasks/${taskId}`)
    } else {
      await axios.delete(`/api/attack/tasks/${taskId}`)
    }
    
    ElMessage.success('删除成功')
    await loadTasks()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('删除任务失败:', error)
      ElMessage.error('删除失败: ' + (error.response?.data?.error || error.message))
    }
  }
}

// 停止当前任务
const stopCurrentTask = async () => {
  if (!currentTask.value) return

  try {
    await axios.post(`/api/attack/tasks/${currentTask.value.id}/stop`)
    ElMessage.success('任务已停止')
    detailVisible.value = false
    await loadTasks()
  } catch (error) {
    ElMessage.error('停止失败: ' + (error.response?.data?.error || error.message))
  }
}

// 删除当前任务
const deleteCurrentTask = async () => {
  if (!currentTask.value) return

  await deleteTask(currentTask.value.id)
  detailVisible.value = false
}

// 清空历史
const clearHistory = async () => {
  try {
    const tasksToDelete = allTasks.value.filter(
      t => t.status === 'completed' || t.status === 'failed' || t.status === 'stopped'
    )

    if (tasksToDelete.length === 0) {
      ElMessage.info('没有可清空的历史任务')
      return
    }

    await ElMessageBox.confirm(
      `确认清空 ${tasksToDelete.length} 个已完成、已失败和已停止的任务？此操作无法恢复。`,
      '确认清空',
      {
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    // 按任务类型分组
    const attackTasks = tasksToDelete.filter(t => t.type !== 'ids')
    const idsTasks = tasksToDelete.filter(t => t.type === 'ids')
    
    console.log('准备清空的任务:', {
      attack: attackTasks.length,
      ids: idsTasks.length,
      total: tasksToDelete.length
    })
    
    let deletedCount = 0
    const batchSize = 1000
    
    // 删除攻击任务
    if (attackTasks.length > 0) {
      const attackTaskIds = attackTasks.map(task => task.id)
      for (let i = 0; i < attackTaskIds.length; i += batchSize) {
        const batchIds = attackTaskIds.slice(i, i + batchSize)
        try {
          await axios.post('/api/attack/tasks/batch-delete', {
            task_ids: batchIds
          })
          deletedCount += batchIds.length
          if (tasksToDelete.length > batchSize) {
            ElMessage.info(`清空进度: ${deletedCount}/${tasksToDelete.length}`)
          }
        } catch (err) {
          console.error('批量删除攻击任务失败:', err.response?.data || err.message)
          throw err
        }
      }
    }
    
    // 删除IDS任务
    if (idsTasks.length > 0) {
      const idsTaskIds = idsTasks.map(task => task.id)
      for (let i = 0; i < idsTaskIds.length; i += batchSize) {
        const batchIds = idsTaskIds.slice(i, i + batchSize)
        try {
          await axios.post('/api/defense/ids/tasks/batch-delete', {
            task_ids: batchIds
          })
          deletedCount += batchIds.length
          if (tasksToDelete.length > batchSize) {
            ElMessage.info(`清空进度: ${deletedCount}/${tasksToDelete.length}`)
          }
        } catch (err) {
          console.error('批量删除IDS任务失败:', err.response?.data || err.message)
          throw err
        }
      }
    }

    ElMessage.success(`已清空 ${deletedCount} 个任务`)
    await loadTasks()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('清空历史失败:', error)
      ElMessage.error('清空失败: ' + (error.response?.data?.error || error.message))
    }
  }
}

// 获取状态类型
const getStatusType = (status) => {
  const types = {
    'running': 'primary',
    'completed': 'success',
    'failed': 'danger',
    'stopped': 'info'
  }
  return types[status] || 'info'
}

// 获取状态文本
const getStatusText = (status) => {
  const texts = {
    'running': '运行中',
    'completed': '已完成',
    'failed': '已失败',
    'stopped': '已停止'
  }
  return texts[status] || status
}

// 获取会话名称
const getSessionName = (task) => {
  if (task.parameters && task.parameters.sessionName) {
    return task.parameters.sessionName
  }
  return task.target || 'N/A'
}

// 获取目标显示
const getTargetDisplay = (task) => {
  return task.target || 'N/A'
}

// 获取IDS任务目标显示
const getIDSTarget = (task) => {
  return task.interface || 'N/A'
}

// 获取异常数量
const getAnomalyCount = (task) => {
  if (task.result && task.result.anomalies !== undefined) {
    return task.result.anomalies
  }
  return 0
}

// 计算成功率
const calculateSuccessRate = (result) => {
  if (!result || !result.packetsSent) return 0
  const failed = result.packetsFailed || 0
  return Math.round(((result.packetsSent - failed) / result.packetsSent) * 100)
}

// 格式化参数键
const formatParamKey = (key) => {
  const keyMap = {
    // 基础参数
    'sessionId': '会话 ID',
    'session_id': '会话 ID',
    'sessionName': '会话名称',
    'session_name': '会话名称',
    'interface': '网络接口',
    'speedMultiplier': '速度倍率',
    'speed_multiplier': '速度倍率',
    'mode': '重放模式',
    'loopCount': '循环次数',
    'loop_count': '循环次数',
    'packetCount': '数据包数量',
    'packet_count': '数据包数量',
    
    // 重放参数
    'duration': '持续时间(秒)',
    'protocolFilter': '协议过滤',
    'protocol_filter': '协议过滤',
    'srcAddrFilter': '源地址过滤',
    'src_addr_filter': '源地址过滤',
    'dstAddrFilter': '目标地址过滤',
    'dst_addr_filter': '目标地址过滤',
    'preserveTimestamp': '保留时间戳',
    'preserve_timestamp': '保留时间戳',
    'modifyChecksum': '修正校验和',
    'modify_checksum': '修正校验和',
    
    // Fuzzing参数
    'target': '目标地址',
    'port': '端口',
    'protocol': '协议',
    'template': '模板',
    'iterations': '迭代次数',
    'mutationRate': '变异率',
    'mutation_rate': '变异率',
    'mutationStrategy': '变异策略',
    'mutation_strategy': '变异策略',
    'timeout': '超时时间(秒)',
    'concurrency': '并发数',
    'anomalyDetection': '异常检测',
    'anomaly_detection': '异常检测'
  }
  return keyMap[key] || key
}

// 格式化参数值
const formatParamValue = (value) => {
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

// 格式化规则名称
const formatRuleName = (rule) => {
  const ruleMap = {
    'port_scan': '端口扫描',
    'dos': 'DoS 攻击',
    'brute_force': '暴力破解',
    'sql_injection': 'SQL 注入',
    'xss': 'XSS 攻击'
  }
  return ruleMap[rule] || rule
}

// 格式化时间
const formatTime = (time) => {
  if (!time) return 'N/A'
  return new Date(time).toLocaleString('zh-CN')
}

// 配置持久化：从 localStorage 加载
const loadSavedConfigs = () => {
  try {
    // 加载 IDS 配置
    const savedIDS = localStorage.getItem('idsConfig')
    if (savedIDS) {
      const config = JSON.parse(savedIDS)
      Object.assign(idsForm.value, config)
    }
    
    // 加载 Replay 配置
    const savedReplay = localStorage.getItem('replayConfig')
    if (savedReplay) {
      const config = JSON.parse(savedReplay)
      Object.assign(replayForm.value, config)
    }
    
    // 加载 Fuzz 配置
    const savedFuzz = localStorage.getItem('fuzzConfig')
    if (savedFuzz) {
      const config = JSON.parse(savedFuzz)
      Object.assign(fuzzForm.value, config)
    }
  } catch (e) {
    console.error('Failed to load saved configs:', e)
  }
}

// 配置持久化：保存到 localStorage
const saveIDSConfig = () => {
  localStorage.setItem('idsConfig', JSON.stringify(idsForm.value))
}

const saveReplayConfig = () => {
  localStorage.setItem('replayConfig', JSON.stringify(replayForm.value))
}

const saveFuzzConfig = () => {
  localStorage.setItem('fuzzConfig', JSON.stringify(fuzzForm.value))
}

// 监听配置变化，自动保存
watch(() => replayForm.value.interface, () => {
  saveReplayConfig()
}, { deep: false })

watch(() => replayForm.value.speedMultiplier, () => {
  saveReplayConfig()
}, { deep: false })

watch(() => replayForm.value.mode, () => {
  saveReplayConfig()
}, { deep: false })

watch(() => idsForm.value, () => {
  saveIDSConfig()
}, { deep: true })

watch(() => fuzzForm.value, () => {
  saveFuzzConfig()
}, { deep: true })

// 初始化
onMounted(() => {
  loadSavedConfigs()  // 先加载保存的配置
  loadSessions()
  loadInterfaces()    // 再加载接口（不会覆盖已保存的配置）
  loadTasks()
  loadFuzzTemplates()
  loadIDSTasks()

  // 每 5 秒刷新任务列表（确保统计数据同步）
  refreshTimer = setInterval(() => {
    // 攻击任务：只在有运行中的任务时才刷新
    const hasRunningAttackTasks = tasks.value.some(t => t.status === 'running')
    if (hasRunningAttackTasks) {
      loadTasks()
    }
    
    // IDS 任务：始终刷新（因为告警可能在其他页面被删除）
    loadIDSTasks()
  }, 5000)
})

// 清理
onUnmounted(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
  }
})
</script>

<style scoped>
.attack {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

:deep(.el-descriptions__label) {
  font-weight: 600;
}

:deep(.el-table) {
  font-size: 13px;
}

:deep(.el-progress__text) {
  font-size: 12px !important;
}
</style>
