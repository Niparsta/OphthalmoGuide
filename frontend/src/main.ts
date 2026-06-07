import { createApp } from 'vue'
import { createNotivue } from 'notivue'
import App from './App.vue'
import { guardAdminShellBeforeMount } from './adminShellGuard'

import 'notivue/notification.css'
import 'notivue/animations.css'

async function bootstrap() {
  await guardAdminShellBeforeMount()

  const app = createApp(App)
  app.use(createNotivue({
    position: 'top-right',
    limit: 5,
  }))
  app.mount('#app')
}

void bootstrap()
