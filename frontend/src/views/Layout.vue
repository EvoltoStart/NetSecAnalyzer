<template>
  <el-container class="layout-container">
    <el-aside width="200px">
      <div class="logo">
        <h2>NetSecAnalyzer</h2>
      </div>
      <el-menu
        :default-active="$route.path"
        class="el-menu-vertical"
        @select="handleSelect"
        router
      >
        <el-menu-item index="/dashboard">
          <el-icon><DataAnalysis /></el-icon>
          <span>仪表盘</span>
        </el-menu-item>
        <el-menu-item index="/capture">
          <el-icon><Monitor /></el-icon>
          <span>数据采集</span>
        </el-menu-item>
        <el-menu-item index="/analyze">
          <el-icon><DataLine /></el-icon>
          <span>协议分析</span>
        </el-menu-item>
        <el-menu-item index="/scan">
          <el-icon><Search /></el-icon>
          <span>漏洞扫描</span>
        </el-menu-item>
        <el-menu-item index="/attack">
          <el-icon><Lightning /></el-icon>
          <span>攻防模拟</span>
        </el-menu-item>
        <el-menu-item index="/ids-alerts">
          <el-icon><Warning /></el-icon>
          <span>IDS 告警</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header>
        <div class="header-content">
          <h3>{{ currentTitle }}</h3>
          <div class="header-right">
            <el-button :icon="RefreshRight" circle @click="refresh" />
          </div>
        </div>
      </el-header>

      <el-main>
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { RefreshRight, Warning } from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()

const currentTitle = computed(() => route.meta.title || '')

const handleSelect = (key) => {
  router.push(key)
}

const refresh = () => {
  router.go(0)
}
</script>

<style scoped>
.layout-container {
  height: 100vh;
}

.el-aside {
  background-color: #304156;
  color: #fff;
}

.logo {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #263445;
}

.logo h2 {
  color: #fff;
  font-size: 18px;
}

.el-menu {
  border-right: none;
  background-color: #304156;
}

.el-menu-item {
  color: #bfcbd9;
}

.el-menu-item.is-active {
  background-color: #263445 !important;
  color: #409eff !important;
}

.el-menu-item:hover {
  background-color: #263445 !important;
  color: #fff !important;
}

.el-header {
  background-color: #fff;
  border-bottom: 1px solid #e6e6e6;
  display: flex;
  align-items: center;
  padding: 0 20px;
}

.header-content {
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.el-main {
  background-color: #f0f2f5;
  padding: 20px;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
