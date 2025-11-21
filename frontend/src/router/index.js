import { createRouter, createWebHistory } from 'vue-router'
import Layout from '@/views/Layout.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      component: Layout,
      redirect: '/dashboard',
      children: [
        {
          path: 'dashboard',
          name: 'Dashboard',
          component: () => import('@/views/Dashboard.vue'),
          meta: { title: '仪表盘' }
        },
        {
          path: 'capture',
          name: 'Capture',
          component: () => import('@/views/Capture.vue'),
          meta: { title: '数据采集' }
        },
        {
          path: 'packets/:id',
          name: 'Packets',
          component: () => import('@/views/Packets.vue'),
          meta: { title: '数据包列表' }
        },
        {
          path: 'analyze',
          name: 'Analyze',
          component: () => import('@/views/Analyze.vue'),
          meta: { title: '协议分析' }
        },
        {
          path: 'scan',
          name: 'Scan',
          component: () => import('@/views/Scan.vue'),
          meta: { title: '漏洞扫描' }
        },
        {
          path: 'scan/results/:id',
          name: 'ScanResults',
          component: () => import('@/views/ScanResults.vue'),
          meta: { title: '扫描结果' }
        },
        {
          path: 'attack',
          name: 'Attack',
          component: () => import('@/views/Attack.vue'),
          meta: { title: '攻防模拟' }
        },
        {
          path: 'ids-alerts',
          name: 'IDSAlerts',
          component: () => import('@/views/IDSAlerts.vue'),
          meta: { title: 'IDS 告警管理' }
        }
      ]
    }
  ]
})

export default router
