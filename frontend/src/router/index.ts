import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import { format, messages } from '@/i18n/messages';

declare module 'vue-router' {
  interface RouteMeta {
    title?: string;
  }
}

const routes: RouteRecordRaw[] = [
  { path: '/', name: 'home', component: () => import('@/views/HomeView.vue'), meta: { title: messages.home.title } },
];

// Dev-only component gallery: the import sits behind the DEV flag, so production builds drop it.
if (import.meta.env.DEV) {
  routes.push({
    path: '/dev/gallery',
    name: 'gallery',
    component: () => import('@/views/dev/GalleryView.vue'),
    meta: { title: 'UI kit gallery' },
  });
}

routes.push({
  path: '/:pathMatch(.*)*',
  name: 'not-found',
  component: () => import('@/views/NotFoundView.vue'),
  meta: { title: messages.notFound.title },
});

export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior: () => ({ top: 0 }),
});

router.afterEach((to) => {
  document.title = to.meta.title ? format(messages.app.pageTitle, { page: to.meta.title }) : messages.app.name;
});
