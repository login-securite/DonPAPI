import { createRouter, createWebHistory } from 'vue-router'
import Cookies from '../components/Cookies.vue'
import Secrets from '../components/Secrets.vue'
import Certificates from '../components/Certificates.vue'
import General from '../components/General.vue'


const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '',
      name: 'general',
      component: General
    },
    {
      path: '/cookies',
      name: 'cookies',
      component: Cookies
    },
    {
      path: '/secrets',
      name: 'secrets',
      component: Secrets
    },
    {
      path: '/certificates',
      name: 'certificates',
      component: Certificates
    },
  ]
})

export default router
