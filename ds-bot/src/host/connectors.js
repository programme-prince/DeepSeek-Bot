// Connector tokens stay in Secrets and reach remote MCP servers only through in-memory headers.
// New tokens are shared with no Bot shell; the tools do not need the tokens there.

export const GITHUB = 'github'
export const GITHUB_SECRET = 'GITHUB_TOKEN'
export const GITEE = 'gitee'
export const GITEE_SECRET = 'GITEE_TOKEN'
const MCP_CLIENT = '@deepseek-ai/dsh-mcp-client'
const CHECK_TIMEOUT_MS = 15_000

const CONNECTORS = {
  [GITHUB]: {
    name: 'GitHub', secret: GITHUB_SECRET,
    defaults: { url: 'https://api.githubcopilot.com/mcp/', api: 'https://api.github.com', toolsets: 'context,repos,issues,pull_requests' },
  },
  [GITEE]: {
    name: 'Gitee', secret: GITEE_SECRET,
    defaults: { url: 'https://api.gitee.com/mcp', api: 'https://gitee.com/api/v5' },
  },
}

async function checkToken(token, name, api, headers, request, scheme = 'Bearer') {
  let response
  try {
    response = await request(`${api.replace(/\/$/, '')}/user`, {
      headers: { Authorization: `${scheme} ${token}`, ...headers },
      signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
    })
  } catch {
    throw new Error(`Could not reach ${name}`)
  }
  if (response.status === 401) throw new Error(`${name} did not accept this token`)
  if (!response.ok) throw new Error(`${name} answered ${response.status}`)
  const user = await response.json().catch(() => ({}))
  if (typeof user?.login !== 'string') throw new Error(`${name} did not say who this token belongs to`)
  return { login: user.login }
}

export function signIn(token, { api = CONNECTORS.github.defaults.api, fetch: request = fetch } = {}) {
  return checkToken(token, 'GitHub', api, { Accept: 'application/vnd.github+json', 'User-Agent': 'ds-bot', 'X-GitHub-Api-Version': '2022-11-28' }, request)
}

export function signInGitee(token, { api = CONNECTORS.gitee.defaults.api, fetch: request = fetch } = {}) {
  return checkToken(token, 'Gitee', api, { Accept: 'application/json' }, request, 'token')
}

export function install(rt) {
  const { ctx, state } = rt
  const entries = Object.entries(CONNECTORS).filter(([id]) => rt.config[id] !== false).map(([id, spec]) => ({
    id, ...spec, options: { ...spec.defaults, ...rt.config[id] },
  }))
  const byId = Object.fromEntries(entries.map(entry => [entry.id, entry]))
  const mounts = Object.fromEntries(entries.map(entry => [entry.id, null]))
  const statuses = Object.fromEntries(entries.map(entry => [entry.id, { state: 'off' }]))
  let queue = Promise.resolve()
  let stopped = false

  const reason = error => {
    const text = [error, error?.cause].filter(Boolean).map(part => String(part?.message ?? part)).join(': ')
    return rt.redactSecrets(text || 'error').slice(0, 300)
  }

  const secure = entry => [entry.options.url, entry.options.api].every(address => /^https:\/\//i.test(String(address)))
  const insecureMessage = entry => `${entry.name} addresses must start with https://`

  async function unmount(id) {
    const fiber = mounts[id]?.fiber
    mounts[id] = null
    if (fiber !== undefined) await Promise.resolve().then(() => fiber.dispose()).catch(() => {})
  }

  async function reconcile(entry, force) {
    const { id, secret, options } = entry
    const token = !stopped ? rt.secretValue(secret) : undefined
    if (!force && mounts[id] !== null && mounts[id].token === token) return
    await unmount(id)
    if (token === undefined) {
      statuses[id] = { state: 'off' }
      return
    }
    if (!secure(entry)) {
      mounts[id] = { token }
      statuses[id] = { state: 'error', error: insecureMessage(entry) }
      return
    }
    statuses[id] = { state: 'connecting' }
    const loader = ctx.get?.('loader')
    if (typeof loader?.import !== 'function' || typeof ctx.plugin !== 'function') {
      mounts[id] = { token }
      statuses[id] = { state: 'error', error: 'This DSH cannot load connectors' }
      return
    }
    try {
      const exports = await loader.import(MCP_CLIENT)
      const plugin = loader.unwrapExports?.(exports) ?? exports?.default ?? exports
      const headers = { Authorization: `Bearer ${token}` }
      if (id === GITHUB) headers['X-MCP-Toolsets'] = options.toolsets
      const fiber = ctx.plugin(plugin, {
        transport: 'streamable-http', serverName: id, url: options.url, headers, failOnStartupError: true,
      })
      mounts[id] = { token, fiber }
      await fiber.await()
      if (mounts[id]?.fiber === fiber) statuses[id] = { state: 'ready' }
    } catch (error) {
      await unmount(id)
      mounts[id] = { token }
      statuses[id] = { state: 'error', error: reason(error) }
      rt.warn(`ds-bot: ${entry.name} connector failed: %s`, statuses[id].error)
    }
  }

  const sync = (id, force = false) => {
    queue = queue.then(async () => {
      for (const entry of entries) if (id === undefined || id === entry.id) await reconcile(entry, force)
    }).catch(error => { rt.warn('ds-bot: connectors: %s', reason(error)) })
    return queue
  }

  const connectorsView = () => entries.map(entry => ({
    id: entry.id, name: entry.name, state: statuses[entry.id].state,
    ...(statuses[entry.id].error !== undefined ? { error: statuses[entry.id].error } : {}),
    account: rt.secretValue(entry.secret) !== undefined ? state.connectors?.[entry.id]?.login ?? null : null,
  }))

  const known = id => {
    const entry = byId[id]
    if (!entry) throw new Error('No such connector')
    return entry
  }

  const endpoints = {
    async 'connector-connect'(body) {
      const entry = known(body.id)
      const token = typeof body.token === 'string' ? body.token.trim() : ''
      if (token === '') throw new Error('Paste a token first')
      if (!secure(entry)) throw new Error(insecureMessage(entry))
      await rt.loadSecrets()
      const kept = rt.secretValue(entry.secret) !== undefined
      const { login } = await (entry.id === GITHUB ? signIn : signInGitee)(token, { api: entry.options.api })
      await rt.secretEndpoint('secret-set', { name: entry.secret, value: token, purpose: `${entry.name} connector`, ...(kept ? {} : { scope: [] }) })
      state.connectors = { ...state.connectors, [entry.id]: { login, connectedAt: Date.now() } }
      await rt.save()
      await sync(entry.id)
      return connectorsView()
    },
    async 'connector-disconnect'(body) {
      const entry = known(body.id)
      await rt.loadSecrets()
      if (rt.secretValue(entry.secret) !== undefined) await rt.secretEndpoint('secret-delete', { name: entry.secret })
      if (state.connectors?.[entry.id] !== undefined) {
        delete state.connectors[entry.id]
        await rt.save()
      }
      await sync(entry.id)
      return connectorsView()
    },
    async 'connector-retry'(body) {
      const entry = known(body.id)
      await rt.loadSecrets()
      await sync(entry.id, true)
      return connectorsView()
    },
  }

  ctx.effect(() => {
    stopped = false
    void rt.loadSecrets().then(() => sync())
    return () => {
      stopped = true
      for (const entry of entries) void unmount(entry.id)
    }
  }, 'ds-bot: connectors')

  Object.assign(rt, { connectorsView, connectorEndpoint: (endpoint, body) => endpoints[endpoint](body ?? {}), secretsChanged: () => { void sync() } })
}
