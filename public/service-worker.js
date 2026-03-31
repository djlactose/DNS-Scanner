const CACHE_NAME = 'dns-scanner-v7';
const STATIC_ASSETS = ['/', '/index.html', '/styles.css', '/manifest.json', '/js/core.js', '/js/auth.js', '/js/dashboard.js', '/js/domains.js', '/js/settings.js'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Skip non-GET requests
  if (event.request.method !== 'GET') return;

  // Network-first for everything — cache is only a fallback for offline
  event.respondWith(
    fetch(event.request).then(response => {
      if (response.ok) {
        const clone = response.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
      }
      return response;
    }).catch(() => caches.match(event.request))
  );
});

self.addEventListener('push', (event) => {
  let data = { title: 'DNS Scanner', body: 'New notification' };
  try { data = event.data.json(); } catch (e) {}

  event.waitUntil(
    self.registration.showNotification(data.title || 'DNS Scanner', {
      body: data.body || '',
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
      data: data.data || {},
      requireInteraction: true,
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then(clients => {
      const client = clients.find(c => c.visibilityState === 'visible');
      if (client) { client.focus(); return; }
      self.clients.openWindow('/');
    })
  );
});
