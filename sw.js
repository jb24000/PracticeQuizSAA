// Service Worker for AWS SAA-C03 Strategic Exam Trainer
// Version 1.0.0 - Professional PWA with offline support

const CACHE_NAME = 'saa-c03-trainer-v1.0.0';
const DYNAMIC_CACHE = 'saa-c03-dynamic-v1.0.0';
const OFFLINE_URL = '/offline.html';

// Core assets to cache immediately on install
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json'
];

// Cache strategies
const CACHE_STRATEGIES = {
  cacheFirst: [
    /\.(?:css|js|woff2?|ttf|otf|eot)$/,
    /^https:\/\/fonts\.googleapis\.com/,
    /^https:\/\/fonts\.gstatic\.com/
  ],
  networkFirst: [
    /\.(?:json)$/,
    /^https:\/\/api\./
  ],
  staleWhileRevalidate: [
    /\.(?:png|jpg|jpeg|svg|gif|webp)$/
  ]
};

// Install event - cache core assets
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Installing...');
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[Service Worker] Caching core assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => {
        console.log('[Service Worker] Skip waiting');
        return self.skipWaiting();
      })
      .catch((error) => {
        console.error('[Service Worker] Installation failed:', error);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activating...');
  
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((cacheName) => {
              return cacheName.startsWith('saa-c03-') && 
                     cacheName !== CACHE_NAME && 
                     cacheName !== DYNAMIC_CACHE;
            })
            .map((cacheName) => {
              console.log('[Service Worker] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            })
        );
      })
      .then(() => {
        console.log('[Service Worker] Claiming clients');
        return self.clients.claim();
      })
  );
});

// Fetch event - implement cache strategies
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip chrome-extension and other non-http(s) requests
  if (!request.url.startsWith('http')) {
    return;
  }

  // Determine cache strategy
  const strategy = getCacheStrategy(request);
  
  event.respondWith(
    handleRequest(request, strategy)
      .catch(() => {
        // If all strategies fail, return offline page for navigation requests
        if (request.mode === 'navigate') {
          return caches.match(OFFLINE_URL);
        }
        // Return a basic error response for other requests
        return new Response('Network error occurred', {
          status: 503,
          statusText: 'Service Unavailable',
          headers: new Headers({
            'Content-Type': 'text/plain'
          })
        });
      })
  );
});

// Determine cache strategy based on request
function getCacheStrategy(request) {
  const url = request.url;
  
  // Check cache-first patterns
  for (const pattern of CACHE_STRATEGIES.cacheFirst) {
    if (pattern.test(url)) {
      return 'cache-first';
    }
  }
  
  // Check network-first patterns
  for (const pattern of CACHE_STRATEGIES.networkFirst) {
    if (pattern.test(url)) {
      return 'network-first';
    }
  }
  
  // Check stale-while-revalidate patterns
  for (const pattern of CACHE_STRATEGIES.staleWhileRevalidate) {
    if (pattern.test(url)) {
      return 'stale-while-revalidate';
    }
  }
  
  // Default strategy for navigation requests
  if (request.mode === 'navigate') {
    return 'network-first';
  }
  
  // Default strategy for everything else
  return 'stale-while-revalidate';
}

// Handle request based on strategy
async function handleRequest(request, strategy) {
  switch (strategy) {
    case 'cache-first':
      return cacheFirst(request);
    case 'network-first':
      return networkFirst(request);
    case 'stale-while-revalidate':
      return staleWhileRevalidate(request);
    default:
      return networkFirst(request);
  }
}

// Cache-first strategy
async function cacheFirst(request) {
  const cachedResponse = await caches.match(request);
  
  if (cachedResponse) {
    console.log('[Service Worker] Cache hit:', request.url);
    return cachedResponse;
  }
  
  console.log('[Service Worker] Cache miss, fetching:', request.url);
  const networkResponse = await fetch(request);
  
  // Cache successful responses
  if (networkResponse.ok) {
    const cache = await caches.open(DYNAMIC_CACHE);
    cache.put(request, networkResponse.clone());
  }
  
  return networkResponse;
}

// Network-first strategy
async function networkFirst(request) {
  try {
    const networkResponse = await fetch(request);
    
    // Cache successful responses
    if (networkResponse.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    console.log('[Service Worker] Network failed, trying cache:', request.url);
    const cachedResponse = await caches.match(request);
    
    if (cachedResponse) {
      return cachedResponse;
    }
    
    throw error;
  }
}

// Stale-while-revalidate strategy
async function staleWhileRevalidate(request) {
  const cachedResponse = await caches.match(request);
  
  const fetchPromise = fetch(request)
    .then(async (networkResponse) => {
      // Update cache with fresh response
      if (networkResponse.ok) {
        const cache = await caches.open(DYNAMIC_CACHE);
        cache.put(request, networkResponse.clone());
      }
      return networkResponse;
    })
    .catch((error) => {
      console.log('[Service Worker] Revalidation failed:', error);
    });
  
  // Return cached response immediately, update cache in background
  return cachedResponse || fetchPromise;
}

// Handle background sync for offline submissions
self.addEventListener('sync', (event) => {
  console.log('[Service Worker] Background sync triggered');
  
  if (event.tag === 'sync-quiz-results') {
    event.waitUntil(syncQuizResults());
  }
});

// Sync quiz results when connection is restored
async function syncQuizResults() {
  try {
    // Get any pending quiz results from IndexedDB
    const pendingResults = await getPendingResults();
    
    if (pendingResults && pendingResults.length > 0) {
      // Send results to server when implemented
      console.log('[Service Worker] Syncing', pendingResults.length, 'quiz results');
      
      // Clear pending results after successful sync
      await clearPendingResults();
    }
  } catch (error) {
    console.error('[Service Worker] Sync failed:', error);
    throw error;
  }
}

// Handle push notifications
self.addEventListener('push', (event) => {
  console.log('[Service Worker] Push received');
  
  const options = {
    title: 'SAA-C03 Study Reminder',
    body: event.data ? event.data.text() : 'Time for your daily AWS practice!',
    icon: '/icon-192x192.png',
    badge: '/badge-72x72.png',
    vibrate: [200, 100, 200],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    },
    actions: [
      {
        action: 'study',
        title: 'Start Studying',
        icon: '/icon-study.png'
      },
      {
        action: 'later',
        title: 'Remind Later',
        icon: '/icon-later.png'
      }
    ]
  };
  
  event.waitUntil(
    self.registration.showNotification(options.title, options)
  );
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
  console.log('[Service Worker] Notification clicked');
  
  event.notification.close();
  
  if (event.action === 'study') {
    // Open the app in exam mode
    event.waitUntil(
      clients.openWindow('/?mode=exam')
    );
  } else if (event.action === 'later') {
    // Schedule another reminder (implementation needed)
    console.log('[Service Worker] Reminder postponed');
  } else {
    // Default action - open the app
    event.waitUntil(
      clients.openWindow('/')
    );
  }
});

// Message handler for client communication
self.addEventListener('message', (event) => {
  console.log('[Service Worker] Message received:', event.data);
  
  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data.type === 'CACHE_URLS') {
    event.waitUntil(
      caches.open(DYNAMIC_CACHE)
        .then((cache) => cache.addAll(event.data.urls))
    );
  }
  
  if (event.data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys()
        .then((cacheNames) => {
          return Promise.all(
            cacheNames.map((cacheName) => {
              if (cacheName !== CACHE_NAME) {
                return caches.delete(cacheName);
              }
            })
          );
        })
    );
  }
});

// Helper functions for IndexedDB operations (placeholder)
async function getPendingResults() {
  // Implementation would retrieve pending quiz results from IndexedDB
  return [];
}

async function clearPendingResults() {
  // Implementation would clear pending results from IndexedDB
  return true;
}

// Cache size management
async function trimCache(cacheName, maxItems) {
  const cache = await caches.open(cacheName);
  const keys = await cache.keys();
  
  if (keys.length > maxItems) {
    // Delete oldest items
    const keysToDelete = keys.slice(0, keys.length - maxItems);
    await Promise.all(
      keysToDelete.map(key => cache.delete(key))
    );
    console.log(`[Service Worker] Trimmed ${keysToDelete.length} items from ${cacheName}`);
  }
}

// Periodic cache cleanup (every 24 hours)
setInterval(() => {
  trimCache(DYNAMIC_CACHE, 50);
}, 24 * 60 * 60 * 1000);

console.log('[Service Worker] Loaded successfully');
