import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import { format, messages } from '@/i18n/messages';

declare module 'vue-router' {
  interface RouteMeta {
    title?: string;
  }
}

export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'home',
    component: () => import('@/views/HomeView.vue'),
    meta: { title: messages.home.title, requiresAuth: true },
  },
  {
    path: '/account/mfa',
    name: 'mfa-enroll',
    component: () => import('@/views/account/MfaEnrollView.vue'),
    meta: { title: messages.mfaEnroll.title, requiresAuth: true },
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/auth/LoginView.vue'),
    meta: { title: messages.login.title, guestOnly: true },
  },
  {
    path: '/login/verify',
    name: 'mfa-challenge',
    component: () => import('@/views/auth/MfaChallengeView.vue'),
    meta: { title: messages.mfaChallenge.title, guestOnly: true },
  },
  {
    path: '/register',
    name: 'register',
    component: () => import('@/views/auth/RegisterView.vue'),
    meta: { title: messages.register.title, guestOnly: true },
  },
  {
    path: '/forgot-password',
    name: 'forgot-password',
    component: () => import('@/views/auth/ForgotPasswordView.vue'),
    meta: { title: messages.forgot.title, guestOnly: true },
  },
  // Reset and verify work signed in or not: the link itself is the credential.
  {
    path: '/reset-password',
    name: 'reset-password',
    component: () => import('@/views/auth/ResetPasswordView.vue'),
    meta: { title: messages.reset.title },
  },
  {
    path: '/verify-email',
    name: 'verify-email',
    component: () => import('@/views/auth/VerifyEmailView.vue'),
    meta: { title: messages.verify.title },
  },
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
