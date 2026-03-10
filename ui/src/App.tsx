import { useState, useEffect, useCallback, useRef, FormEvent } from 'react'

/* ── Types ─────────────────────────────────────────────────────── */

type Tab = 'cicd' | 'prod' | 'dev' | 'onboarding'

interface ServiceHealth {
  status: string
}

interface Status {
  service: string
  time: string
  orders: ServiceHealth
  inventory: ServiceHealth
}

interface Order {
  id: number
  product: string
  quantity: number
  status: string
  created_at: string
}

interface InventoryItem {
  name: string
  stock: number
  updated_at: string
}

interface ActivityEntry {
  id: number
  message: string
  timestamp: Date
  type: 'order' | 'stock'
}

interface AuthUser {
  authenticated: boolean
  email?: string
  name?: string
  id?: string
}

interface IntegrationStatus {
  auth0_configured: boolean
  callback_url?: string
  stripe_webhook_configured: boolean
  stripe_payments_enabled: boolean
  webhook_url?: string
}

interface LogEntry {
  id: number
  service: string
  message: string
  timestamp: Date
  level: 'info' | 'warn' | 'error'
}

interface ApiResult {
  status: number
  body: string
  time: number
}

/* ── Helpers ───────────────────────────────────────────────────── */

let nextActivityId = 0
let nextLogId = 0

function timeAgo(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000)
  if (seconds < 5) return 'just now'
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  return `${Math.floor(seconds / 3600)}h ago`
}

function isHealthy(s?: ServiceHealth): boolean {
  return !!s?.status?.includes('ok')
}

const TABS: { key: Tab; label: string; icon: string }[] = [
  { key: 'prod', label: 'Prod', icon: '📊' },
  { key: 'dev', label: 'Dev', icon: '🛠' },
  { key: 'cicd', label: 'CI / CD', icon: '🚀' },
  { key: 'onboarding', label: 'Onboarding', icon: '📖' },
]

const API_PRESETS = [
  { label: 'GET /api/status', method: 'GET', url: '/api/status' },
  { label: 'GET /api/orders', method: 'GET', url: '/api/orders' },
  { label: 'GET /api/inventory', method: 'GET', url: '/api/inventory' },
  { label: 'POST /api/orders', method: 'POST', url: '/api/orders', body: '{"product":"widget-a","quantity":1}' },
]

const SERVICES = ['gateway', 'orders', 'inventory', 'ui']

const ONBOARDING_STEPS = [
  { title: 'Install Kindling CLI', cmd: 'brew install kindlingdev/tap/kindling', docs: 'https://github.com/kindlingdev/kindling' },
  { title: 'Init cluster', cmd: 'kindling init', docs: '' },
  { title: 'Register runner', cmd: 'kindling runners -u <user> -r <repo> -t <pat>', docs: '' },
  { title: 'Generate workflow', cmd: 'kindling generate -k <api-key> -r .', docs: '' },
  { title: 'Deploy', cmd: 'kindling deploy -f .kindling/dev-environment.yaml', docs: '' },
  { title: 'Live sync', cmd: 'kindling sync -d <deploy>', docs: '' },
  { title: 'Debug', cmd: 'kindling debug -d <deploy> --port 5678', docs: '' },
]

/* ── App ───────────────────────────────────────────────────────── */

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('prod')
  const [status, setStatus] = useState<Status | null>(null)
  const [orders, setOrders] = useState<Order[]>([])
  const [inventory, setInventory] = useState<InventoryItem[]>([])
  const [activity, setActivity] = useState<ActivityEntry[]>([])
  const [product, setProduct] = useState('widget-a')
  const [quantity, setQuantity] = useState(1)
  const [submitting, setSubmitting] = useState(false)
  const [toast, setToast] = useState<{
    message: string
    type: 'success' | 'error'
  } | null>(null)
  const [connected, setConnected] = useState(true)
  const prevStock = useRef<Map<string, number>>(new Map())

  // Auth + integrations
  const [authUser, setAuthUser] = useState<AuthUser | null>(null)
  const [integrations, setIntegrations] = useState<IntegrationStatus | null>(null)

  // Payments
  const [payingOrder, setPayingOrder] = useState<number | null>(null)

  // Dev tab state
  const [apiMethod, setApiMethod] = useState('GET')
  const [apiUrl, setApiUrl] = useState('/api/status')
  const [apiBody, setApiBody] = useState('')
  const [apiResult, setApiResult] = useState<ApiResult | null>(null)
  const [apiLoading, setApiLoading] = useState(false)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [logFilter, setLogFilter] = useState<string>('all')

  /* ── Toast helper ────────────────────────────────────────────── */

  const showToast = useCallback(
    (message: string, type: 'success' | 'error' = 'success') => {
      setToast({ message, type })
      setTimeout(() => setToast(null), 3000)
    },
    [],
  )

  /* ── Push a log entry (used to surface system events) ────────── */

  const pushLog = useCallback(
    (service: string, message: string, level: LogEntry['level'] = 'info') => {
      setLogs((prev) =>
        [{ id: ++nextLogId, service, message, timestamp: new Date(), level }, ...prev].slice(0, 200),
      )
    },
    [],
  )

  /* ── Data fetching ───────────────────────────────────────────── */

  const fetchData = useCallback(async () => {
    try {
      const [statusRes, ordersRes, inventoryRes] = await Promise.all([
        fetch('/api/status'),
        fetch('/api/orders'),
        fetch('/api/inventory'),
      ])

      if (statusRes.ok) setStatus(await statusRes.json())
      if (ordersRes.ok) {
        const data = await ordersRes.json()
        setOrders(Array.isArray(data) ? data : data.orders ?? [])
      }

      if (inventoryRes.ok) {
        const data = await inventoryRes.json()
        const items: InventoryItem[] = Array.isArray(data) ? data : data.products ?? []
        setInventory(items)

        // Track stock deltas for the activity log
        if (prevStock.current.size > 0) {
          const newEntries: ActivityEntry[] = []
          for (const item of items) {
            const prev = prevStock.current.get(item.name)
            if (prev !== undefined && prev !== item.stock) {
              const delta = item.stock - prev
              newEntries.push({
                id: ++nextActivityId,
                message: `${item.name}: ${prev} → ${item.stock} (${delta > 0 ? '+' : ''}${delta})`,
                timestamp: new Date(),
                type: 'stock',
              })
            }
          }
          if (newEntries.length > 0) {
            setActivity((prev) => [...newEntries, ...prev].slice(0, 50))
          }
        }
        prevStock.current = new Map(items.map((i) => [i.name, i.stock]))
      }

      setConnected(true)
    } catch {
      setConnected(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 3000)
    return () => clearInterval(id)
  }, [fetchData])

  /* ── Auth + integration status ─────────────────────────────── */

  useEffect(() => {
    async function fetchAuth() {
      try {
        const [meRes, authStatusRes, stripeRes] = await Promise.all([
          fetch('/api/auth/me'),
          fetch('/api/auth/status'),
          fetch('/api/stripe/status'),
        ])
        if (meRes.ok) setAuthUser(await meRes.json())
        const authData = authStatusRes.ok ? await authStatusRes.json() : {}
        const stripeData = stripeRes.ok ? await stripeRes.json() : {}
        setIntegrations({
          auth0_configured: authData.auth0_configured ?? false,
          callback_url: authData.callback_url,
          stripe_webhook_configured: stripeData.stripe_webhook_configured ?? false,
          stripe_payments_enabled: stripeData.stripe_payments_enabled ?? false,
          webhook_url: stripeData.webhook_url,
        })
      } catch { /* auth endpoints may not exist yet */ }
    }
    fetchAuth()
    const id = setInterval(fetchAuth, 15000)
    return () => clearInterval(id)
  }, [])

  /* ── Payment ─────────────────────────────────────────────────── */

  const payOrder = useCallback(async (orderId: number) => {
    setPayingOrder(orderId)
    try {
      const res = await fetch('/payments/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: orderId, amount: 1000 }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Payment failed')
      showToast(`Payment ${data.id} succeeded for order #${orderId}`)
      pushLog('stripe', `PaymentIntent ${data.id} created for order #${orderId} ($${(data.amount / 100).toFixed(2)})`)
      setActivity((prev) =>
        [{
          id: ++nextActivityId,
          message: `💳 Payment for order #${orderId}: $${(data.amount / 100).toFixed(2)}`,
          timestamp: new Date(),
          type: 'order' as const,
        }, ...prev].slice(0, 50),
      )
      // Refresh data so order status updates when webhook fires
      setTimeout(fetchData, 2000)
    } catch (err: any) {
      showToast(err.message || 'Payment failed', 'error')
      pushLog('stripe', `Payment failed for order #${orderId}: ${err.message}`, 'error')
    } finally {
      setPayingOrder(null)
    }
  }, [showToast, pushLog, fetchData])

  /* ── Order creation ──────────────────────────────────────────── */

  const createOrder = async (e: FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    try {
      const res = await fetch('/api/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ product, quantity }),
      })
      if (!res.ok) throw new Error('Failed to create order')
      const order: Order = await res.json()

      showToast(`Order #${order.id} placed — ${order.product} ×${order.quantity}`)
      pushLog('orders', `Order #${order.id} created: ${order.product} ×${order.quantity}`)
      setActivity((prev) =>
        [
          {
            id: ++nextActivityId,
            message: `Order #${order.id}: ${order.product} ×${order.quantity}`,
            timestamp: new Date(),
            type: 'order' as const,
          },
          ...prev,
        ].slice(0, 50),
      )

      setTimeout(fetchData, 500)
      setTimeout(fetchData, 3000)
    } catch {
      showToast('Failed to create order', 'error')
      pushLog('orders', 'Failed to create order', 'error')
    } finally {
      setSubmitting(false)
    }
  }

  /* ── API Explorer ────────────────────────────────────────────── */

  const sendApiRequest = async (e: FormEvent) => {
    e.preventDefault()
    setApiLoading(true)
    const start = performance.now()
    try {
      const opts: RequestInit = { method: apiMethod }
      if (apiMethod === 'POST' && apiBody) {
        opts.headers = { 'Content-Type': 'application/json' }
        opts.body = apiBody
      }
      const res = await fetch(apiUrl, opts)
      const text = await res.text()
      let pretty = text
      try { pretty = JSON.stringify(JSON.parse(text), null, 2) } catch { /* not json */ }
      setApiResult({ status: res.status, body: pretty, time: Math.round(performance.now() - start) })
      pushLog('gateway', `${apiMethod} ${apiUrl} → ${res.status} (${Math.round(performance.now() - start)}ms)`)
    } catch (err) {
      setApiResult({ status: 0, body: String(err), time: Math.round(performance.now() - start) })
      pushLog('gateway', `${apiMethod} ${apiUrl} → FAILED`, 'error')
    } finally {
      setApiLoading(false)
    }
  }

  /* ── Derived values ──────────────────────────────────────────── */

  const maxStock = Math.max(...inventory.map((i) => i.stock), 1)
  const filteredLogs = logFilter === 'all' ? logs : logs.filter((l) => l.service === logFilter)

  /* ── Render ──────────────────────────────────────────────────── */

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <svg className="logo" viewBox="0 0 32 32" width="28" height="28">
            <defs>
              <linearGradient id="flame" x1="0" y1="1" x2="0" y2="0">
                <stop offset="0%" stopColor="#f97316" />
                <stop offset="100%" stopColor="#fbbf24" />
              </linearGradient>
            </defs>
            <path d="M16 2c0 0-6 8-6 14a6 6 0 0012 0c0-6-6-14-6-14z" fill="url(#flame)" />
            <path d="M16 12c0 0-3 4-3 7a3 3 0 006 0c0-3-3-7-3-7z" fill="rgba(255,255,255,0.2)" />
          </svg>
          <h1>Kindling <span className="subtle">Dashboard</span></h1>
        </div>

        {/* Tab Navigation */}
        <nav className="tab-nav">
          {TABS.map((t) => (
            <button
              key={t.key}
              className={`tab-btn ${activeTab === t.key ? 'active' : ''}`}
              onClick={() => setActiveTab(t.key)}
            >
              <span className="tab-icon">{t.icon}</span>
              {t.label}
            </button>
          ))}
        </nav>

        <div className="header-right">
          {authUser?.authenticated ? (
            <div className="auth-info">
              <span className="auth-name">{authUser.name || authUser.email}</span>
              <a href="/api/auth/logout" className="auth-btn logout">Logout</a>
            </div>
          ) : integrations?.auth0_configured ? (
            <a href="/api/auth/login" className="auth-btn login">Login</a>
          ) : null}
          <span className={`connection-dot ${connected ? 'ok' : 'err'}`} />
          <span className="connection-label">
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </header>

      {/* ═══════════════════════════════════════════════════════════
           PROD — Service health, orders, inventory, activity
         ═══════════════════════════════════════════════════════════ */}
      {activeTab === 'prod' && (
        <>
          {/* Status Bar */}
          <div className="status-bar">
            {[
              { name: 'Gateway', ok: !!status },
              { name: 'Orders', ok: isHealthy(status?.orders) },
              { name: 'Inventory', ok: isHealthy(status?.inventory) },
            ].map((svc) => (
              <div key={svc.name} className={`status-chip ${svc.ok ? 'ok' : 'err'}`}>
                <span className="status-dot" />
                {svc.name}
              </div>
            ))}
            {status && (
              <span className="status-time">
                Last check: {new Date(status.time).toLocaleTimeString()}
              </span>
            )}
          </div>

          <main className="dashboard">
            {/* Orders column */}
            <section className="panel">
              <h2>📦 Place Order</h2>
              <form className="order-form" onSubmit={createOrder}>
                <div className="form-row">
                  <label>
                    Product
                    <select value={product} onChange={(e) => setProduct(e.target.value)}>
                      {(inventory.length > 0
                        ? inventory.map((i) => i.name)
                        : ['widget-a', 'widget-b', 'gadget-x']
                      ).map((name) => (
                        <option key={name} value={name}>{name}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Qty
                    <input type="number" min={1} max={999} value={quantity} onChange={(e) => setQuantity(Number(e.target.value))} />
                  </label>
                  <button type="submit" disabled={submitting}>
                    {submitting ? 'Placing…' : 'Place Order'}
                  </button>
                </div>
              </form>

              <h2>📋 Recent Orders</h2>
              <div className="orders-list">
                {orders.length === 0 ? (
                  <p className="empty">No orders yet — place one above!</p>
                ) : (
                  <table>
                    <thead>
                      <tr><th>#</th><th>Product</th><th>Qty</th><th>Status</th><th>Time</th>{integrations?.stripe_payments_enabled && <th></th>}</tr>
                    </thead>
                    <tbody>
                      {orders.map((o) => (
                        <tr key={o.id}>
                          <td className="mono">{o.id}</td>
                          <td>{o.product}</td>
                          <td className="mono">{o.quantity}</td>
                          <td><span className={`badge ${o.status}`}>{o.status}</span></td>
                          <td className="subtle">{new Date(o.created_at).toLocaleTimeString()}</td>
                          {integrations?.stripe_payments_enabled && (
                            <td>
                              {o.status !== 'paid' && (
                                <button
                                  className="pay-btn"
                                  disabled={payingOrder === o.id}
                                  onClick={() => payOrder(o.id)}
                                >
                                  {payingOrder === o.id ? '…' : '💳 Pay'}
                                </button>
                              )}
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </section>

            {/* Inventory + Activity column */}
            <section className="panel">
              <h2>📊 Inventory</h2>
              <div className="inventory-grid">
                {inventory.map((item) => (
                  <div key={item.name} className="inventory-card">
                    <div className="inventory-header">
                      <span className="inventory-name">{item.name}</span>
                      <span className="inventory-stock">{item.stock}</span>
                    </div>
                    <div className="stock-bar">
                      <div className="stock-fill" style={{ width: `${(item.stock / maxStock) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>

              <h2>⚡ Activity</h2>
              <div className="activity-log">
                {activity.length === 0 ? (
                  <p className="empty">Activity will appear here as orders flow through the system</p>
                ) : (
                  activity.map((entry) => (
                    <div key={entry.id} className={`activity-entry ${entry.type}`}>
                      <span className="activity-icon">{entry.type === 'order' ? '📦' : '📉'}</span>
                      <span className="activity-message">{entry.message}</span>
                      <span className="activity-time">{timeAgo(entry.timestamp)}</span>
                    </div>
                  ))
                )}
              </div>
            </section>
          </main>

          {/* Integrations strip */}
          {integrations && (
            <div className="integrations-strip">
              <h3>Integrations</h3>
              <div className="integration-cards">
                <div className={`integration-card ${integrations.auth0_configured ? 'configured' : ''}`}>
                  <span className="integration-icon">🔐</span>
                  <div>
                    <strong>Auth0</strong>
                    <span className={`integration-status ${integrations.auth0_configured ? 'ok' : ''}`}>
                      {integrations.auth0_configured ? 'Connected' : 'Not configured'}
                    </span>
                    {integrations.callback_url && (
                      <code className="integration-url">{integrations.callback_url}</code>
                    )}
                  </div>
                </div>
                <div className={`integration-card ${integrations.stripe_webhook_configured ? 'configured' : ''}`}>
                  <span className="integration-icon">💳</span>
                  <div>
                    <strong>Stripe Webhooks</strong>
                    <span className={`integration-status ${integrations.stripe_webhook_configured ? 'ok' : ''}`}>
                      {integrations.stripe_webhook_configured ? 'Connected' : 'Not configured'}
                    </span>
                    {integrations.webhook_url && (
                      <code className="integration-url">{integrations.webhook_url}</code>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* ═══════════════════════════════════════════════════════════
           DEV — API Explorer + Logs side by side
         ═══════════════════════════════════════════════════════════ */}
      {activeTab === 'dev' && (
        <main className="dashboard">
          {/* API Explorer */}
          <section className="panel">
            <h2>🔍 API Explorer</h2>
            <div className="card">
              <div className="preset-bar">
                {API_PRESETS.map((p) => (
                  <button
                    key={p.label}
                    className={`preset-btn ${apiUrl === p.url && apiMethod === p.method ? 'active' : ''}`}
                    onClick={() => { setApiMethod(p.method); setApiUrl(p.url); setApiBody(p.body ?? '') }}
                  >
                    <span className={`method-tag ${p.method.toLowerCase()}`}>{p.method}</span>
                    {p.url}
                  </button>
                ))}
              </div>

              <form className="api-form" onSubmit={sendApiRequest}>
                <div className="api-row">
                  <select value={apiMethod} onChange={(e) => setApiMethod(e.target.value)}>
                    <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option>
                  </select>
                  <input
                    className="api-url"
                    value={apiUrl}
                    onChange={(e) => setApiUrl(e.target.value)}
                    placeholder="/api/..."
                  />
                  <button type="submit" disabled={apiLoading}>
                    {apiLoading ? 'Sending…' : 'Send'}
                  </button>
                </div>
                {(apiMethod === 'POST' || apiMethod === 'PUT') && (
                  <textarea
                    className="api-body"
                    rows={4}
                    value={apiBody}
                    onChange={(e) => setApiBody(e.target.value)}
                    placeholder='{"key":"value"}'
                  />
                )}
              </form>

              {apiResult && (
                <div className="api-result">
                  <div className="api-result-header">
                    <span className={`api-status ${apiResult.status >= 200 && apiResult.status < 300 ? 'ok' : 'err'}`}>
                      {apiResult.status || 'ERR'}
                    </span>
                    <span className="api-timing">{apiResult.time}ms</span>
                  </div>
                  <pre className="api-response">{apiResult.body}</pre>
                </div>
              )}
            </div>

            {/* Environment quick-look */}
            <h2>🌐 Environment</h2>
            <div className="card env-grid">
              {[
                { name: 'Gateway', ok: !!status },
                { name: 'Orders', ok: isHealthy(status?.orders) },
                { name: 'Inventory', ok: isHealthy(status?.inventory) },
              ].map((svc) => (
                <div key={svc.name} className={`env-card ${svc.ok ? 'ok' : 'err'}`}>
                  <span className={`env-dot ${svc.ok ? 'ok' : 'err'}`} />
                  <span className="env-name">{svc.name}</span>
                  <span className="env-status">{svc.ok ? 'Healthy' : 'Down'}</span>
                </div>
              ))}
            </div>
          </section>

          {/* Logs */}
          <section className="panel">
            <h2>📝 Logs</h2>
            <div className="card log-panel">
              <div className="log-toolbar">
                <select value={logFilter} onChange={(e) => setLogFilter(e.target.value)}>
                  <option value="all">All services</option>
                  {SERVICES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
                <button className="btn-subtle" onClick={() => setLogs([])}>Clear</button>
              </div>
              <div className="log-stream">
                {filteredLogs.length === 0 ? (
                  <p className="empty">Logs will appear here as you interact with the system</p>
                ) : (
                  filteredLogs.map((l) => (
                    <div key={l.id} className={`log-entry ${l.level}`}>
                      <span className="log-time">{l.timestamp.toLocaleTimeString()}</span>
                      <span className={`log-svc svc-${l.service}`}>{l.service}</span>
                      <span className="log-msg">{l.message}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </section>
        </main>
      )}

      {/* ═══════════════════════════════════════════════════════════
           CI / CD — Pipeline overview
         ═══════════════════════════════════════════════════════════ */}
      {activeTab === 'cicd' && (
        <main className="dashboard single-col">
          <section className="panel">
            <h2>🚀 Pipeline Overview</h2>
            <div className="pipeline-cards">
              {SERVICES.map((svc) => {
                const ok = svc === 'gateway' ? !!status
                  : svc === 'orders' ? isHealthy(status?.orders)
                  : svc === 'inventory' ? isHealthy(status?.inventory)
                  : true
                return (
                  <div key={svc} className="pipeline-card">
                    <div className="pipeline-header">
                      <span className="pipeline-name">{svc}</span>
                      <span className={`badge ${ok ? 'confirmed' : 'failed'}`}>{ok ? 'deployed' : 'unhealthy'}</span>
                    </div>
                    <div className="pipeline-stages">
                      {['Build', 'Push', 'Deploy'].map((stage) => (
                        <div key={stage} className="pipeline-stage ok">
                          <span className="stage-dot" />
                          {stage}
                        </div>
                      ))}
                    </div>
                    <div className="pipeline-meta">
                      <span className="mono">localhost:5001/{svc}:latest</span>
                    </div>
                  </div>
                )
              })}
            </div>

            <h2>🔧 Quick Actions</h2>
            <div className="card quick-actions">
              <div className="action-row">
                <code>kindling deploy -f .kindling/dev-environment.yaml</code>
                <span className="action-desc">Full deploy</span>
              </div>
              <div className="action-row">
                <code>kindling push -s &lt;service&gt;</code>
                <span className="action-desc">Rebuild one service</span>
              </div>
              <div className="action-row">
                <code>kindling status</code>
                <span className="action-desc">Check everything</span>
              </div>
              <div className="action-row">
                <code>kindling logs</code>
                <span className="action-desc">Tail controller logs</span>
              </div>
            </div>
          </section>
        </main>
      )}

      {/* ═══════════════════════════════════════════════════════════
           ONBOARDING — Getting started
         ═══════════════════════════════════════════════════════════ */}
      {activeTab === 'onboarding' && (
        <main className="dashboard single-col">
          <section className="panel">
            <h2>📖 Getting Started</h2>
            <div className="onboard-steps">
              {ONBOARDING_STEPS.map((step, i) => (
                <div key={i} className="onboard-step">
                  <div className="step-number">{i + 1}</div>
                  <div className="step-content">
                    <div className="step-title">{step.title}</div>
                    <code className="step-cmd">{step.cmd}</code>
                  </div>
                </div>
              ))}
            </div>

            <h2>🗺 Architecture</h2>
            <div className="card arch-diagram">
              <pre>{`
  ┌──────────┐     ┌──────────┐     ┌───────────┐
  │    UI    │────▶│ Gateway  │────▶│  Orders   │
  │ (Vite)  │     │  (Go)    │     │ (Python)  │
  └──────────┘     └────┬─────┘     └─────┬─────┘
                        │                 │
                        │           ┌─────▼─────┐
                        └──────────▶│ Inventory │
                                    │  (Node)   │
                                    └───────────┘
              `}</pre>
            </div>

            <h2>📋 CLI Quick Reference</h2>
            <div className="card cli-ref">
              {[
                ['kindling init', 'Create Kind cluster + operator'],
                ['kindling deploy', 'Deploy staging environment'],
                ['kindling sync', 'Live-sync files into running pod'],
                ['kindling debug', 'Attach debugger to a service'],
                ['kindling dev', 'Dev server with hot reload'],
                ['kindling push', 'Rebuild & deploy one service'],
                ['kindling status', 'View environment status'],
                ['kindling logs', 'Tail controller logs'],
                ['kindling secrets set', 'Store K8s secrets'],
                ['kindling env set', 'Set environment variable'],
                ['kindling expose', 'HTTPS tunnel for OAuth'],
                ['kindling destroy', 'Tear it all down'],
              ].map(([cmd, desc]) => (
                <div key={cmd} className="cli-row">
                  <code>{cmd}</code>
                  <span>{desc}</span>
                </div>
              ))}
            </div>
          </section>
        </main>
      )}

      {/* Toast Notification */}
      {toast && (
        <div className={`toast ${toast.type}`}>
          {toast.type === 'success' ? '✅' : '❌'} {toast.message}
        </div>
      )}
    </div>
  )
}
