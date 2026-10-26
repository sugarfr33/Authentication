import { createPinia } from 'pinia';
import { createApp } from 'vue';
import './styles/tokens.css';
import './styles/base.css';
import { onSessionExpired } from './api';
import App from './App.vue';
import { useToast } from './composables/useToast';
import { messages } from './i18n/messages';
import { router } from './router';
import { useSessionStore } from './stores/session';

const app = createApp(App);
const pinia = createPinia();
app.use(pinia).use(router);

// A silent refresh found the session over (expired, revoked or ended in another tab).
const session = useSessionStore(pinia);
onSessionExpired(() => {
  const wasSignedIn = session.isAuthenticated;
  session.clear();
  if (wasSignedIn) useToast().show(messages.auth.sessionExpired, { tone: 'warning' });
});

app.mount('#app');
