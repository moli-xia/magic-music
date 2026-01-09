const fs = require('node:fs')
const http = require('node:http')
const https = require('node:https')
const net = require('node:net')
const path = require('node:path')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')

const ROOT_DIR = path.resolve(__dirname)
const PORT = Number(process.env.PORT || '8099')

const DB_PATH = path.resolve(process.env.DB_PATH || path.join(ROOT_DIR, 'magic-music-db.json'))
const sessions = new Map()
const adminSessions = new Map()
const captchaStore = new Map()
const CAPTCHA_TTL_MS = 3 * 60 * 1000
const CAPTCHA_MAX_ATTEMPTS = 6

const KUGOU_UPSTREAMS = [
  { hostname: '127.0.0.1', port: 3000, stripPrefix: '/kugou' },
  { hostname: '127.0.0.1', port: 3101, stripPrefix: '/kugou' },
  { hostname: '127.0.0.1', port: 3102, stripPrefix: '/kugou' },
  { hostname: '127.0.0.1', port: 3001, stripPrefix: '/kugou' },
]

const NETEASE_HOST = String(process.env.NETEASE_HOST || '127.0.0.1')
const NETEASE_PORT = Number(process.env.NETEASE_PORT || '3002')

const DEFAULT_ADMIN_USERNAME = 'admin'
const DEFAULT_ADMIN_PASSWORD = 'admin123456'

function readJsonFileSafe(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback
    const raw = fs.readFileSync(filePath, 'utf8')
    if (!raw) return fallback
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed : fallback
  } catch {
    return fallback
  }
}

function writeJsonFileSafe(filePath, data) {
  const payload = JSON.stringify(data, null, 2)
  fs.writeFileSync(filePath, payload, 'utf8')
}

function loadDb() {
  const db = readJsonFileSafe(DB_PATH, null)
  const base = {
    users: [],
    playlistsByUser: {},
    likesByUser: {},
    downloadsByUser: {},
    recentsByUser: {},
    nextUserId: 1,
    nextPlaylistId: 1,
    homeSlides: [],
    homePlaylists: {},
    nextHomeSlideId: 1,
    nextHomePlaylistId: 1,
    kugouAuth: null,
    admin: null,
  }
  if (!db) return base
  if (db && typeof db === 'object') {
    if (db.playlistsByUser == null) db.playlistsByUser = {}
    if (db.likesByUser == null) db.likesByUser = {}
    if (db.downloadsByUser == null) db.downloadsByUser = {}
    if (db.recentsByUser == null) db.recentsByUser = {}
    if (db.nextUserId == null) db.nextUserId = 1
    if (db.nextPlaylistId == null) db.nextPlaylistId = 1
    if (db.homeSlides == null) db.homeSlides = []
    if (db.homePlaylists == null) db.homePlaylists = {}
    if (db.nextHomeSlideId == null) db.nextHomeSlideId = 1
    if (db.nextHomePlaylistId == null) db.nextHomePlaylistId = 1
    if (db.kugouAuth === undefined) db.kugouAuth = null
    if (db.admin === undefined) db.admin = null
  }
  return { ...base, ...db }
}

function saveDb(db) {
  writeJsonFileSafe(DB_PATH, db)
}

function parseCookies(header) {
  const out = {}
  const raw = String(header || '')
  if (!raw) return out
  const parts = raw.split(';')
  for (const p of parts) {
    const idx = p.indexOf('=')
    if (idx <= 0) continue
    const k = p.slice(0, idx).trim()
    const v = p.slice(idx + 1).trim()
    if (!k) continue
    out[k] = decodeURIComponent(v)
  }
  return out
}

function setCookie(res, name, value, options) {
  const opts = options || {}
  const parts = [`${name}=${encodeURIComponent(String(value || ''))}`]
  parts.push('Path=/')
  if (opts.httpOnly !== false) parts.push('HttpOnly')
  parts.push('SameSite=Lax')
  if (opts.maxAge != null) parts.push(`Max-Age=${Math.max(0, Number(opts.maxAge) || 0)}`)
  if (opts.expires) parts.push(`Expires=${opts.expires.toUTCString()}`)
  const prev = res.getHeader('Set-Cookie')
  const next = Array.isArray(prev) ? prev.concat(parts.join('; ')) : prev ? [prev, parts.join('; ')] : [parts.join('; ')]
  res.setHeader('Set-Cookie', next)
}

function readBody(req) {
  return new Promise(resolve => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', () => resolve(''))
  })
}

function sendJsonWithHeaders(res, statusCode, payload, headers) {
  const extra = headers && typeof headers === 'object' ? headers : {}
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8', ...extra })
  res.end(JSON.stringify(payload))
}

function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex')
  const hash = crypto.scryptSync(String(password || ''), s, 32).toString('hex')
  return { salt: s, hash }
}

function safeUserPublic(u) {
  if (!u) return null
  return { id: u.id, username: u.username, createdAt: u.createdAt }
}

function sanitizeTrack(track) {
  if (!track || typeof track !== 'object') return null
  const platform = String(track.platform || '').slice(0, 30)
  const id = String(track.id || '').slice(0, 80)
  if (!platform || !id) return null
  return {
    platform,
    id,
    name: String(track.name || '').slice(0, 200),
    artist: String(track.artist || '').slice(0, 200),
    album: String(track.album || '').slice(0, 200),
    coverUrl: String(track.coverUrl || '').slice(0, 500),
    album_audio_id: String(track.album_audio_id || '').slice(0, 80),
  }
}

function safeHomePlaylistPublic(pl) {
  if (!pl || typeof pl !== 'object') return null
  return {
    id: String(pl.id || ''),
    name: String(pl.name || ''),
    tracks: Array.isArray(pl.tracks) ? pl.tracks.map(sanitizeTrack).filter(Boolean) : [],
    createdAt: String(pl.createdAt || ''),
    updatedAt: String(pl.updatedAt || ''),
  }
}

function sanitizeHomeSlideInput(input) {
  if (!input || typeof input !== 'object') return null
  const playlistId = String(input.playlistId || '').slice(0, 80)
  const imageUrl = String(input.imageUrl || '').slice(0, 2000)
  const imageDataUrl = String(input.imageDataUrl || '').slice(0, 3_000_000)
  if (!playlistId) return null
  if (!imageUrl && !imageDataUrl) return null
  return {
    playlistId,
    imageUrl,
    imageDataUrl,
  }
}

function requireUser(req, res) {
  const cookies = parseCookies(req.headers.cookie)
  const token = cookies.mm_session || ''
  const userId = token ? sessions.get(token) : null
  if (!userId) {
    sendJson(res, 401, { error: 'Unauthorized' })
    return null
  }
  return String(userId)
}

function requireAdmin(req, res) {
  const cookies = parseCookies(req.headers.cookie)
  const token = cookies.mm_admin_session || ''
  const admin = token ? adminSessions.get(token) : null
  if (!admin) {
    sendJson(res, 401, { error: 'Unauthorized' })
    return null
  }
  return String(admin.username || '')
}

function ensureAdminAccount(db) {
  if (db && typeof db === 'object' && db.admin && typeof db.admin === 'object' && db.admin.salt && db.admin.hash) return false
  const envUsername = String(process.env.ADMIN_USERNAME || '').trim()
  const envPassword = String(process.env.ADMIN_PASSWORD || '')
  const username = envUsername || DEFAULT_ADMIN_USERNAME
  const password = envPassword || DEFAULT_ADMIN_PASSWORD
  const { salt, hash } = hashPassword(password)
  db.admin = {
    username,
    salt,
    hash,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }
  return true
}

function verifyAdminPassword(db, username, password) {
  const admin = db && typeof db === 'object' ? db.admin : null
  if (!admin || typeof admin !== 'object') return false
  if (String(admin.username || '') !== String(username || '')) return false
  if (!admin.salt || !admin.hash) return false
  const { hash } = hashPassword(String(password || ''), admin.salt)
  return hash === admin.hash
}

function buildCookieHeader(obj) {
  if (!obj || typeof obj !== 'object') return ''
  return Object.entries(obj)
    .filter(([k, v]) => k && v != null && String(v) !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
    .join('; ')
}

function pickKugouAuthCookieJar(auth) {
  if (!auth || typeof auth !== 'object') return {}
  const out = {}
  ;['token', 'userid', 'vip_type', 'vip_token', 'dfid'].forEach(k => {
    const v = auth[k]
    if (v != null && String(v) !== '') out[k] = String(v)
  })
  return out
}

function httpRequestBuffer(options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, res => {
      const chunks = []
      res.on('data', c => chunks.push(c))
      res.on('end', () => resolve({ statusCode: res.statusCode || 502, headers: res.headers || {}, buffer: Buffer.concat(chunks) }))
    })
    req.on('error', reject)
    req.setTimeout(6000, () => req.destroy(new Error('timeout')))
    if (body && body.length) req.end(body)
    else req.end()
  })
}

const KUGOU_BUNDLED_APP = path.join(ROOT_DIR, 'magic-music', 'KuGouMusicApi', 'app.js')
let kugouChild = null
let kugouEnsurePromise = null
let kugouReady = false
let kugouAuthEnsurePromise = null

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function parseSetCookieHeader(setCookieHeader) {
  const jar = {}
  if (!setCookieHeader) return jar
  const arr = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader]
  for (const raw of arr) {
    if (!raw) continue
    const first = String(raw).split(';')[0] || ''
    const idx = first.indexOf('=')
    if (idx <= 0) continue
    const k = first.slice(0, idx).trim()
    const vRaw = first.slice(idx + 1).trim()
    if (!k) continue
    let v = vRaw
    try {
      v = decodeURIComponent(vRaw)
    } catch {}
    jar[k] = v
  }
  return jar
}

function randomInt(min, max) {
  const a = Math.floor(Number(min) || 0)
  const b = Math.floor(Number(max) || 0)
  const lo = Math.min(a, b)
  const hi = Math.max(a, b)
  const span = hi - lo + 1
  if (span <= 1) return lo
  return lo + (crypto.randomBytes(4).readUInt32BE(0) % span)
}

function randomCaptchaText(length) {
  const n = Math.max(4, Math.min(8, Number(length) || 5))
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  let out = ''
  for (let i = 0; i < n; i += 1) out += chars[randomInt(0, chars.length - 1)]
  return out
}

function svgEscape(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function buildCaptchaSvg(text) {
  const width = 120
  const height = 40
  const bg = `rgb(${randomInt(236, 248)},${randomInt(236, 248)},${randomInt(236, 248)})`
  const strokes = []
  for (let i = 0; i < 4; i += 1) {
    const x1 = randomInt(0, width)
    const y1 = randomInt(0, height)
    const x2 = randomInt(0, width)
    const y2 = randomInt(0, height)
    const a = randomInt(18, 40)
    strokes.push(`<path d="M${x1} ${y1} L${x2} ${y2}" stroke="rgba(30,30,40,0.${a})" stroke-width="${randomInt(1, 2)}" fill="none"/>`)
  }

  const dots = []
  for (let i = 0; i < 14; i += 1) {
    dots.push(`<circle cx="${randomInt(0, width)}" cy="${randomInt(0, height)}" r="${randomInt(1, 2)}" fill="rgba(30,30,40,0.18)"/>`)
  }

  let x = 10
  const letters = []
  for (const ch of String(text || '')) {
    x += 20
    const y = randomInt(24, 33)
    const rot = randomInt(-18, 18)
    const size = randomInt(18, 22)
    letters.push(
      `<text x="${x}" y="${y}" font-family="Verdana,Arial,sans-serif" font-size="${size}" font-weight="700" fill="rgba(10,10,16,0.92)" transform="rotate(${rot} ${x} ${y})">${svgEscape(ch)}</text>`,
    )
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="captcha"><rect width="${width}" height="${height}" rx="8" fill="${bg}"/>${strokes.join('')}${dots.join('')}${letters.join('')}</svg>`
}

function cleanupCaptchaStore(now) {
  const t = Number(now) || Date.now()
  for (const [id, rec] of captchaStore.entries()) {
    if (!rec || typeof rec !== 'object') {
      captchaStore.delete(id)
      continue
    }
    if (!rec.expiresAt || t >= rec.expiresAt) captchaStore.delete(id)
  }
}

function issueCaptcha() {
  cleanupCaptchaStore(Date.now())
  const id = crypto.randomBytes(16).toString('hex')
  const text = randomCaptchaText(5)
  captchaStore.set(id, { answer: text, createdAt: Date.now(), expiresAt: Date.now() + CAPTCHA_TTL_MS, attempts: 0 })
  return { id, svg: buildCaptchaSvg(text) }
}

function verifyCaptcha(id, code) {
  cleanupCaptchaStore(Date.now())
  const key = String(id || '').trim()
  const raw = String(code || '').trim().toUpperCase()
  if (!key || !raw) return { ok: false, error: '请输入验证码' }
  const rec = captchaStore.get(key)
  if (!rec || typeof rec !== 'object') return { ok: false, error: '验证码已过期，请刷新' }
  if (rec.expiresAt && Date.now() >= rec.expiresAt) {
    captchaStore.delete(key)
    return { ok: false, error: '验证码已过期，请刷新' }
  }
  rec.attempts = Number(rec.attempts || 0) + 1
  if (rec.attempts > CAPTCHA_MAX_ATTEMPTS) {
    captchaStore.delete(key)
    return { ok: false, error: '验证码尝试次数过多，请刷新' }
  }
  const expected = String(rec.answer || '').toUpperCase()
  if (!expected || expected.length !== raw.length) return { ok: false, error: '验证码错误' }
  const a = Buffer.from(expected)
  const b = Buffer.from(raw)
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b)
  if (!ok) return { ok: false, error: '验证码错误' }
  captchaStore.delete(key)
  return { ok: true }
}

async function probeKugouUpstream(hostname, port) {
  try {
    const r = await httpRequestBuffer({
      hostname,
      port,
      method: 'GET',
      path: '/search?keywords=test&page=1&pagesize=1&type=song',
      headers: { host: `${hostname}:${port}` },
    })
    if (r.statusCode === 404) return false
    if (r.statusCode >= 500) return false
    return true
  } catch {
    return false
  }
}

async function ensureKugouApiReady() {
  if (kugouReady) return true
  if (kugouEnsurePromise) return kugouEnsurePromise
  kugouEnsurePromise = (async () => {
    for (const t of KUGOU_UPSTREAMS) {
      if (await probeKugouUpstream(t.hostname, t.port)) {
        kugouReady = true
        return true
      }
    }

    if (!fs.existsSync(KUGOU_BUNDLED_APP)) return false

    const desiredPorts = [3101, 3102]
    for (const port of desiredPorts) {
      if (await probeKugouUpstream('127.0.0.1', port)) {
        kugouReady = true
        return true
      }

      const child = spawn(process.execPath, [KUGOU_BUNDLED_APP], {
        env: {
          ...process.env,
          PORT: String(port),
          HOST: '127.0.0.1',
          platform: process.env.platform || 'lite',
        },
        stdio: ['ignore', 'inherit', 'inherit'],
      })

      const startedAt = Date.now()
      while (Date.now() - startedAt < 5000) {
        if (await probeKugouUpstream('127.0.0.1', port)) {
          kugouChild = child
          child.on('exit', () => {
            if (kugouChild === child) kugouChild = null
            kugouReady = false
          })
          kugouReady = true
          return true
        }
        await sleep(250)
      }

      try {
        child.kill()
      } catch {}
    }

    return false
  })().finally(() => {
    kugouEnsurePromise = null
  })
  return kugouEnsurePromise
}

async function ensureKugouAuthReady(db) {
  const auth = db && typeof db === 'object' ? db.kugouAuth : null
  const token = auth && typeof auth === 'object' ? String(auth.token || '') : ''
  const userid = auth && typeof auth === 'object' ? String(auth.userid || '') : ''
  const dfid = auth && typeof auth === 'object' ? String(auth.dfid || '') : ''
  if (!token || !userid || dfid) return

  if (kugouAuthEnsurePromise) return kugouAuthEnsurePromise
  kugouAuthEnsurePromise = (async () => {
    const ts = Date.now()
    const refreshResp = await requestKugouJson(
      `/login/token?token=${encodeURIComponent(token)}&userid=${encodeURIComponent(userid)}&timestamp=${ts}`,
    )
    if (refreshResp.statusCode !== 200) return
    const cookieJar = parseSetCookieHeader(refreshResp.headers?.['set-cookie'])
    const nextDfid = cookieJar.dfid != null && String(cookieJar.dfid) !== '' ? String(cookieJar.dfid) : crypto.randomBytes(16).toString('hex')
    const vipType = refreshResp.body?.data?.vip_type ?? auth.vip_type
    const vipToken = refreshResp.body?.data?.vip_token ?? auth.vip_token
    db.kugouAuth = {
      ...auth,
      token: String(cookieJar.token || auth.token || token),
      userid: String(cookieJar.userid || auth.userid || userid),
      vip_type: vipType != null ? String(vipType) : String(auth.vip_type || ''),
      vip_token: vipToken != null ? String(vipToken) : String(auth.vip_token || ''),
      dfid: nextDfid,
      updatedAt: new Date().toISOString(),
    }
    saveDb(db)
  })().finally(() => {
    kugouAuthEnsurePromise = null
  })
  return kugouAuthEnsurePromise
}

async function requestKugouJson(upstreamPath) {
  for (const target of KUGOU_UPSTREAMS) {
    try {
      const r = await httpRequestBuffer({
        hostname: target.hostname,
        port: target.port,
        method: 'GET',
        path: upstreamPath,
        headers: { host: `${target.hostname}:${target.port}` },
      })
      if (r.statusCode === 404) continue
      let body = null
      const raw = r.buffer.toString('utf8')
      try {
        body = JSON.parse(raw)
      } catch {
        body = raw
      }
      return { statusCode: r.statusCode, headers: r.headers, body }
    } catch {
      continue
    }
  }
  return { statusCode: 502, headers: {}, body: { error: 'Bad Gateway', message: 'All upstreams failed' } }
}

async function handleApi(req, res) {
  const requestUrl = new URL(req.url, `http://${req.headers.host}`)
  if (!requestUrl.pathname.startsWith('/api/')) return false

  const db = loadDb()
  const method = req.method || 'GET'
  const pathname = requestUrl.pathname
  const parts = pathname.split('/').filter(Boolean)

  const jsonBody = async () => {
    const raw = await readBody(req)
    if (!raw) return {}
    try {
      const parsed = JSON.parse(raw)
      return parsed && typeof parsed === 'object' ? parsed : {}
    } catch {
      return {}
    }
  }

  if (pathname === '/api/auth/captcha' && method === 'GET') {
    const captcha = issueCaptcha()
    sendJsonWithHeaders(res, 200, { ok: true, id: captcha.id, svg: captcha.svg }, { 'Cache-Control': 'no-store' })
    return true
  }

  if (pathname === '/api/admin/login' && method === 'POST') {
    const created = ensureAdminAccount(db)
    if (created) saveDb(db)
    const body = await jsonBody()
    const username = String(body.username || '').trim()
    const password = String(body.password || '')
    if (!verifyAdminPassword(db, username, password)) {
      sendJson(res, 401, { error: '用户名或密码错误' })
      return true
    }
    const token = crypto.randomBytes(24).toString('hex')
    adminSessions.set(token, { username, createdAt: Date.now() })
    setCookie(res, 'mm_admin_session', token, { maxAge: 60 * 60 * 6 })
    sendJson(res, 200, { ok: true, admin: { username } })
    return true
  }

  if (pathname === '/api/admin/password' && method === 'POST') {
    const adminName = requireAdmin(req, res)
    if (!adminName) return true
    const body = await jsonBody()
    const oldPassword = String(body.oldPassword || '')
    const newPassword = String(body.newPassword || '')
    if (!newPassword || newPassword.length < 8 || newPassword.length > 64) {
      sendJson(res, 400, { error: '新密码长度需为 8-64' })
      return true
    }
    if (!verifyAdminPassword(db, adminName, oldPassword)) {
      sendJson(res, 401, { error: '旧密码错误' })
      return true
    }
    const { salt, hash } = hashPassword(newPassword)
    db.admin = {
      username: String(db.admin?.username || adminName),
      salt,
      hash,
      createdAt: db.admin?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }
    saveDb(db)
    sendJson(res, 200, { ok: true })
    return true
  }

  if (pathname === '/api/admin/logout' && method === 'POST') {
    const cookies = parseCookies(req.headers.cookie)
    const token = cookies.mm_admin_session || ''
    if (token) adminSessions.delete(token)
    setCookie(res, 'mm_admin_session', '', { maxAge: 0, expires: new Date(0) })
    sendJson(res, 200, { ok: true })
    return true
  }

  if (pathname === '/api/admin/me' && method === 'GET') {
    const cookies = parseCookies(req.headers.cookie)
    const token = cookies.mm_admin_session || ''
    const admin = token ? adminSessions.get(token) : null
    sendJson(res, 200, { ok: true, admin: admin ? { username: admin.username } : null })
    return true
  }

  if (pathname === '/api/admin/users' && method === 'GET') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const users = Array.isArray(db.users) ? db.users : []
    const out = users
      .map(u => {
        const pub = safeUserPublic(u)
        if (!pub) return null
        const uid = String(pub.id || '')
        const playlists = Array.isArray(db.playlistsByUser?.[uid]) ? db.playlistsByUser[uid] : []
        const likes = Array.isArray(db.likesByUser?.[uid]) ? db.likesByUser[uid] : []
        const downloads = Array.isArray(db.downloadsByUser?.[uid]) ? db.downloadsByUser[uid] : []
        const recents = Array.isArray(db.recentsByUser?.[uid]) ? db.recentsByUser[uid] : []
        return { ...pub, playlistsCount: playlists.length, likesCount: likes.length, downloadsCount: downloads.length, recentsCount: recents.length }
      })
      .filter(Boolean)
    sendJson(res, 200, { ok: true, users: out })
    return true
  }

  if (parts.length === 4 && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'users' && method === 'DELETE') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const userId = String(parts[3] || '')
    const idx = Array.isArray(db.users) ? db.users.findIndex(u => u && String(u.id) === userId) : -1
    if (idx < 0) {
      sendJson(res, 404, { error: '用户不存在' })
      return true
    }
    db.users.splice(idx, 1)
    delete db.playlistsByUser[userId]
    delete db.likesByUser[userId]
    delete db.downloadsByUser[userId]
    delete db.recentsByUser[userId]
    saveDb(db)
    sendJson(res, 200, { ok: true })
    return true
  }

  if (parts.length === 5 && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'users' && parts[4] === 'password' && method === 'POST') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const userId = String(parts[3] || '')
    const body = await jsonBody()
    const newPassword = String(body.newPassword || '')
    if (!newPassword || newPassword.length < 6 || newPassword.length > 64) {
      sendJson(res, 400, { error: '密码长度需为 6-64' })
      return true
    }
    const user = Array.isArray(db.users) ? db.users.find(u => u && String(u.id) === userId) : null
    if (!user) {
      sendJson(res, 404, { error: '用户不存在' })
      return true
    }
    const { salt, hash } = hashPassword(newPassword)
    user.salt = salt
    user.hash = hash
    saveDb(db)
    sendJson(res, 200, { ok: true })
    return true
  }

  if (pathname === '/api/admin/kugou/auth' && method === 'GET') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const auth = db.kugouAuth && typeof db.kugouAuth === 'object' ? db.kugouAuth : null
    const maskedToken = auth?.token ? `${String(auth.token).slice(0, 6)}...${String(auth.token).slice(-6)}` : ''
    sendJson(res, 200, {
      ok: true,
      auth: auth
        ? {
            userid: String(auth.userid || ''),
            token: maskedToken,
            vip_type: auth.vip_type != null ? String(auth.vip_type) : '',
            updatedAt: auth.updatedAt || '',
          }
        : null,
    })
    return true
  }

  if (pathname === '/api/home/slides' && method === 'GET') {
    const slides = Array.isArray(db.homeSlides) ? db.homeSlides : []
    const out = slides
      .map(s => {
        if (!s || typeof s !== 'object') return null
        return {
          id: String(s.id || ''),
          playlistId: String(s.playlistId || ''),
          imageUrl: String(s.imageUrl || ''),
          imageDataUrl: String(s.imageDataUrl || ''),
        }
      })
      .filter(s => s && s.playlistId && (s.imageUrl || s.imageDataUrl))
    sendJson(res, 200, { ok: true, slides: out })
    return true
  }

  if (parts.length === 4 && parts[0] === 'api' && parts[1] === 'home' && parts[2] === 'playlists' && method === 'GET') {
    const playlistId = String(parts[3] || '')
    const plRaw = db.homePlaylists && typeof db.homePlaylists === 'object' ? db.homePlaylists[playlistId] : null
    const playlist = safeHomePlaylistPublic(plRaw)
    if (!playlist || !playlist.id) {
      sendJson(res, 404, { error: '歌单不存在' })
      return true
    }
    sendJson(res, 200, { ok: true, playlist })
    return true
  }

  if (pathname === '/api/admin/home/slides' && method === 'GET') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const slides = Array.isArray(db.homeSlides) ? db.homeSlides : []
    const out = slides
      .map(s => {
        if (!s || typeof s !== 'object') return null
        return {
          id: String(s.id || ''),
          playlistId: String(s.playlistId || ''),
          imageUrl: String(s.imageUrl || ''),
          imageDataUrl: String(s.imageDataUrl || ''),
          createdAt: String(s.createdAt || ''),
          updatedAt: String(s.updatedAt || ''),
        }
      })
      .filter(Boolean)
    sendJson(res, 200, { ok: true, slides: out })
    return true
  }

  if (pathname === '/api/admin/home/slides' && method === 'POST') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const body = await jsonBody()
    const input = sanitizeHomeSlideInput(body)
    if (!input) {
      sendJson(res, 400, { error: '参数错误' })
      return true
    }
    const exists = db.homePlaylists && typeof db.homePlaylists === 'object' ? db.homePlaylists[input.playlistId] : null
    if (!exists) {
      sendJson(res, 400, { error: '歌单不存在' })
      return true
    }
    const slide = {
      id: String(db.nextHomeSlideId++),
      playlistId: input.playlistId,
      imageUrl: input.imageUrl,
      imageDataUrl: input.imageDataUrl,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }
    const list = Array.isArray(db.homeSlides) ? db.homeSlides : []
    list.unshift(slide)
    db.homeSlides = list
    saveDb(db)
    sendJson(res, 200, { ok: true, slide })
    return true
  }

  if (parts.length === 5 && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'home' && parts[3] === 'slides' && method === 'PUT') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const slideId = String(parts[4] || '')
    const list = Array.isArray(db.homeSlides) ? db.homeSlides : []
    const idx = list.findIndex(s => s && String(s.id) === slideId)
    if (idx < 0) {
      sendJson(res, 404, { error: '幻灯片不存在' })
      return true
    }
    const body = await jsonBody()
    const input = sanitizeHomeSlideInput({ ...list[idx], ...body, playlistId: body.playlistId ?? list[idx].playlistId })
    if (!input) {
      sendJson(res, 400, { error: '参数错误' })
      return true
    }
    const exists = db.homePlaylists && typeof db.homePlaylists === 'object' ? db.homePlaylists[input.playlistId] : null
    if (!exists) {
      sendJson(res, 400, { error: '歌单不存在' })
      return true
    }
    list[idx] = { ...list[idx], ...input, updatedAt: new Date().toISOString() }
    db.homeSlides = list
    saveDb(db)
    sendJson(res, 200, { ok: true, slide: list[idx] })
    return true
  }

  if (parts.length === 5 && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'home' && parts[3] === 'slides' && method === 'DELETE') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const slideId = String(parts[4] || '')
    const list = Array.isArray(db.homeSlides) ? db.homeSlides : []
    const idx = list.findIndex(s => s && String(s.id) === slideId)
    if (idx < 0) {
      sendJson(res, 404, { error: '幻灯片不存在' })
      return true
    }
    list.splice(idx, 1)
    db.homeSlides = list
    saveDb(db)
    sendJson(res, 200, { ok: true })
    return true
  }

  if (pathname === '/api/admin/home/playlists' && method === 'POST') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const body = await jsonBody()
    const name = String(body.name || '').trim()
    if (!name || name.length > 60) {
      sendJson(res, 400, { error: '歌单名称不合法' })
      return true
    }
    const id = String(db.nextHomePlaylistId++)
    const now = new Date().toISOString()
    const pl = { id, name, tracks: [], createdAt: now, updatedAt: now }
    if (!db.homePlaylists || typeof db.homePlaylists !== 'object') db.homePlaylists = {}
    db.homePlaylists[id] = pl
    saveDb(db)
    sendJson(res, 200, { ok: true, playlist: safeHomePlaylistPublic(pl) })
    return true
  }

  if (pathname === '/api/admin/home/playlists' && method === 'GET') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const raw = db.homePlaylists && typeof db.homePlaylists === 'object' ? db.homePlaylists : {}
    const list = Object.values(raw)
      .map(safeHomePlaylistPublic)
      .filter(Boolean)
      .map(p => ({ ...p, tracksCount: Array.isArray(p.tracks) ? p.tracks.length : 0 }))
    sendJson(res, 200, { ok: true, playlists: list })
    return true
  }

  if (parts.length === 5 && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'home' && parts[3] === 'playlists' && method === 'GET') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const playlistId = String(parts[4] || '')
    const plRaw = db.homePlaylists && typeof db.homePlaylists === 'object' ? db.homePlaylists[playlistId] : null
    const playlist = safeHomePlaylistPublic(plRaw)
    if (!playlist || !playlist.id) {
      sendJson(res, 404, { error: '歌单不存在' })
      return true
    }
    sendJson(res, 200, { ok: true, playlist })
    return true
  }

  if (parts.length === 5 && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'home' && parts[3] === 'playlists' && method === 'DELETE') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const playlistId = String(parts[4] || '')
    const raw = db.homePlaylists && typeof db.homePlaylists === 'object' ? db.homePlaylists : null
    if (!raw || !raw[playlistId]) {
      sendJson(res, 404, { error: '歌单不存在' })
      return true
    }
    delete raw[playlistId]
    db.homePlaylists = raw
    const slides = Array.isArray(db.homeSlides) ? db.homeSlides : []
    db.homeSlides = slides.filter(s => !(s && String(s.playlistId) === playlistId))
    saveDb(db)
    sendJson(res, 200, { ok: true })
    return true
  }

  if (parts.length === 7 && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'home' && parts[3] === 'playlists' && parts[5] === 'tracks' && parts[6] === 'add' && method === 'POST') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const playlistId = String(parts[4] || '')
    const body = await jsonBody()
    const track = sanitizeTrack(body.track)
    if (!track) {
      sendJson(res, 400, { error: '参数错误' })
      return true
    }
    if (!db.homePlaylists || typeof db.homePlaylists !== 'object') db.homePlaylists = {}
    const pl = db.homePlaylists[playlistId]
    if (!pl || typeof pl !== 'object') {
      sendJson(res, 404, { error: '歌单不存在' })
      return true
    }
    const tracks = Array.isArray(pl.tracks) ? pl.tracks.map(sanitizeTrack).filter(Boolean) : []
    const key = `${track.platform}:${track.id}`
    const idx = tracks.findIndex(t => t && `${t.platform}:${t.id}` === key)
    if (idx >= 0) tracks.splice(idx, 1)
    tracks.unshift(track)
    pl.tracks = tracks.slice(0, 500)
    pl.updatedAt = new Date().toISOString()
    db.homePlaylists[playlistId] = pl
    saveDb(db)
    sendJson(res, 200, { ok: true, playlist: safeHomePlaylistPublic(pl) })
    return true
  }

  if (parts.length === 7 && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'home' && parts[3] === 'playlists' && parts[5] === 'tracks' && parts[6] === 'remove' && method === 'POST') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const playlistId = String(parts[4] || '')
    const body = await jsonBody()
    const platform = String(body.platform || '').slice(0, 30)
    const id = String(body.id || '').slice(0, 80)
    if (!platform || !id) {
      sendJson(res, 400, { error: '参数错误' })
      return true
    }
    if (!db.homePlaylists || typeof db.homePlaylists !== 'object') db.homePlaylists = {}
    const pl = db.homePlaylists[playlistId]
    if (!pl || typeof pl !== 'object') {
      sendJson(res, 404, { error: '歌单不存在' })
      return true
    }
    const tracks = Array.isArray(pl.tracks) ? pl.tracks.map(sanitizeTrack).filter(Boolean) : []
    const key = `${platform}:${id}`
    const idx = tracks.findIndex(t => t && `${t.platform}:${t.id}` === key)
    if (idx >= 0) tracks.splice(idx, 1)
    pl.tracks = tracks
    pl.updatedAt = new Date().toISOString()
    db.homePlaylists[playlistId] = pl
    saveDb(db)
    sendJson(res, 200, { ok: true, playlist: safeHomePlaylistPublic(pl) })
    return true
  }

  if (pathname === '/api/admin/kugou/clear' && method === 'POST') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    db.kugouAuth = null
    saveDb(db)
    sendJson(res, 200, { ok: true })
    return true
  }

  if (pathname === '/api/admin/kugou/qr/start' && method === 'POST') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const ts = Date.now()
    const keyResp = await requestKugouJson(`/login/qr/key?timestamp=${ts}`)
    if (keyResp.statusCode !== 200 || !keyResp.body) {
      sendJson(res, 502, { error: '获取二维码 key 失败', upstream: keyResp.body })
      return true
    }

    const key =
      keyResp.body?.data?.qrcode ||
      keyResp.body?.data?.key ||
      keyResp.body?.data?.qrcode_key ||
      keyResp.body?.data?.qrcodeKey ||
      ''

    if (!key) {
      sendJson(res, 502, { error: '获取二维码 key 失败', upstream: keyResp.body })
      return true
    }

    const createResp = await requestKugouJson(`/login/qr/create?key=${encodeURIComponent(String(key))}&qrimg=1&timestamp=${ts}`)
    if (createResp.statusCode !== 200 || !createResp.body) {
      sendJson(res, 502, { error: '生成二维码失败', upstream: createResp.body })
      return true
    }

    const data = createResp.body?.data || {}
    sendJson(res, 200, { ok: true, key: String(key), qrcode: { url: String(data.url || ''), base64: String(data.base64 || '') } })
    return true
  }

  if (pathname === '/api/admin/kugou/qr/poll' && method === 'GET') {
    const admin = requireAdmin(req, res)
    if (!admin) return true
    const key = String(requestUrl.searchParams.get('key') || '')
    if (!key) {
      sendJson(res, 400, { error: 'Missing key' })
      return true
    }
    const ts = Date.now()
    const checkResp = await requestKugouJson(`/login/qr/check?key=${encodeURIComponent(key)}&timestamp=${ts}`)
    if (checkResp.statusCode !== 200 || !checkResp.body) {
      sendJson(res, 502, { error: '检查二维码状态失败', upstream: checkResp.body })
      return true
    }

    const status = Number(checkResp.body?.data?.status ?? -1)
    const token = String(checkResp.body?.data?.token || '')
    const userid = String(checkResp.body?.data?.userid || '')

    if (status === 4 && token && userid) {
      const refreshResp = await requestKugouJson(`/login/token?token=${encodeURIComponent(token)}&userid=${encodeURIComponent(userid)}&timestamp=${ts}`)
      const vipType = refreshResp.body?.data?.vip_type ?? checkResp.body?.data?.vip_type
      const vipToken = refreshResp.body?.data?.vip_token ?? checkResp.body?.data?.vip_token
      const cookieJar = parseSetCookieHeader(refreshResp.headers?.['set-cookie'])
      db.kugouAuth = {
        token: String(cookieJar.token || token),
        userid: String(cookieJar.userid || userid),
        vip_type: vipType != null ? String(vipType) : '',
        vip_token: vipToken != null ? String(vipToken) : '',
        dfid: cookieJar.dfid != null && String(cookieJar.dfid) !== '' ? String(cookieJar.dfid) : crypto.randomBytes(16).toString('hex'),
        updatedAt: new Date().toISOString(),
      }
      saveDb(db)
      sendJson(res, 200, { ok: true, status, saved: true })
      return true
    }

    sendJson(res, 200, { ok: true, status, saved: false })
    return true
  }

  if (pathname === '/api/auth/register' && method === 'POST') {
    const body = await jsonBody()
    const cap = verifyCaptcha(body.captchaId, body.captchaCode)
    if (!cap.ok) {
      sendJson(res, 400, { error: cap.error || '验证码错误' })
      return true
    }
    const username = String(body.username || '').trim()
    const password = String(body.password || '')
    if (!username || username.length < 3 || username.length > 20) {
      sendJson(res, 400, { error: '用户名长度需为 3-20' })
      return true
    }
    if (!password || password.length < 6 || password.length > 64) {
      sendJson(res, 400, { error: '密码长度需为 6-64' })
      return true
    }
    const exists = db.users.some(u => u && u.username === username)
    if (exists) {
      sendJson(res, 409, { error: '用户名已存在' })
      return true
    }
    const { salt, hash } = hashPassword(password)
    const user = { id: String(db.nextUserId++), username, salt, hash, createdAt: new Date().toISOString() }
    db.users.push(user)
    db.playlistsByUser[user.id] = []
    db.likesByUser[user.id] = []
    db.downloadsByUser[user.id] = []
    db.recentsByUser[user.id] = []
    saveDb(db)
    if (body.autoLogin === true) {
      const token = crypto.randomBytes(24).toString('hex')
      sessions.set(token, user.id)
      setCookie(res, 'mm_session', token, { maxAge: 60 * 60 * 24 * 7 })
    }
    sendJson(res, 200, { ok: true, user: safeUserPublic(user) })
    return true
  }

  if (pathname === '/api/auth/login' && method === 'POST') {
    const body = await jsonBody()
    const cap = verifyCaptcha(body.captchaId, body.captchaCode)
    if (!cap.ok) {
      sendJson(res, 400, { error: cap.error || '验证码错误' })
      return true
    }
    const username = String(body.username || '').trim()
    const password = String(body.password || '')
    const user = db.users.find(u => u && u.username === username)
    if (!user) {
      sendJson(res, 401, { error: '用户名或密码错误' })
      return true
    }
    const { hash } = hashPassword(password, user.salt)
    if (hash !== user.hash) {
      sendJson(res, 401, { error: '用户名或密码错误' })
      return true
    }
    const token = crypto.randomBytes(24).toString('hex')
    sessions.set(token, user.id)
    setCookie(res, 'mm_session', token, { maxAge: 60 * 60 * 24 * 7 })
    sendJson(res, 200, { ok: true, user: safeUserPublic(user) })
    return true
  }

  if (pathname === '/api/auth/logout' && method === 'POST') {
    const cookies = parseCookies(req.headers.cookie)
    const token = cookies.mm_session || ''
    if (token) sessions.delete(token)
    setCookie(res, 'mm_session', '', { maxAge: 0, expires: new Date(0) })
    sendJson(res, 200, { ok: true })
    return true
  }

  if (pathname === '/api/auth/me' && method === 'GET') {
    const cookies = parseCookies(req.headers.cookie)
    const token = cookies.mm_session || ''
    const userId = token ? sessions.get(token) : null
    const user = userId ? db.users.find(u => u && String(u.id) === String(userId)) : null
    sendJson(res, 200, { ok: true, user: safeUserPublic(user) })
    return true
  }

  if (pathname === '/api/user/playlists' && method === 'GET') {
    const userId = requireUser(req, res)
    if (!userId) return true
    sendJson(res, 200, { ok: true, playlists: db.playlistsByUser[userId] || [] })
    return true
  }

  if (pathname === '/api/user/playlists' && method === 'POST') {
    const userId = requireUser(req, res)
    if (!userId) return true
    const body = await jsonBody()
    const name = String(body.name || '').trim()
    if (!name || name.length > 40) {
      sendJson(res, 400, { error: '歌单名称不合法' })
      return true
    }
    const pl = { id: String(db.nextPlaylistId++), name, tracks: [], createdAt: new Date().toISOString() }
    const list = Array.isArray(db.playlistsByUser[userId]) ? db.playlistsByUser[userId] : []
    list.unshift(pl)
    db.playlistsByUser[userId] = list
    saveDb(db)
    sendJson(res, 200, { ok: true, playlist: pl, playlists: list })
    return true
  }

  if (pathname === '/api/user/playlists/add' && method === 'POST') {
    const userId = requireUser(req, res)
    if (!userId) return true
    const body = await jsonBody()
    const playlistId = String(body.playlistId || '')
    const track = sanitizeTrack(body.track)
    if (!playlistId || !track) {
      sendJson(res, 400, { error: '参数错误' })
      return true
    }
    const list = Array.isArray(db.playlistsByUser[userId]) ? db.playlistsByUser[userId] : []
    const idx = list.findIndex(p => p && String(p.id) === playlistId)
    if (idx < 0) {
      sendJson(res, 404, { error: '歌单不存在' })
      return true
    }
    const pl = list[idx]
    const tracks = Array.isArray(pl.tracks) ? pl.tracks : []
    const key = `${track.platform}:${track.id}`
    if (!tracks.some(t => t && `${t.platform}:${t.id}` === key)) tracks.unshift(track)
    list[idx] = { ...pl, tracks }
    db.playlistsByUser[userId] = list
    saveDb(db)
    sendJson(res, 200, { ok: true, playlist: list[idx] })
    return true
  }

  if (pathname === '/api/user/playlists/remove' && method === 'POST') {
    const userId = requireUser(req, res)
    if (!userId) return true
    const body = await jsonBody()
    const playlistId = String(body.playlistId || '')
    const track = sanitizeTrack(body.track)
    if (!playlistId || !track) {
      sendJson(res, 400, { error: '参数错误' })
      return true
    }
    const list = Array.isArray(db.playlistsByUser[userId]) ? db.playlistsByUser[userId] : []
    const idx = list.findIndex(p => p && String(p.id) === playlistId)
    if (idx < 0) {
      sendJson(res, 404, { error: '歌单不存在' })
      return true
    }
    const pl = list[idx]
    const tracks = Array.isArray(pl.tracks) ? pl.tracks : []
    const key = `${track.platform}:${track.id}`
    const tIdx = tracks.findIndex(t => t && `${t.platform}:${t.id}` === key)
    if (tIdx >= 0) tracks.splice(tIdx, 1)
    list[idx] = { ...pl, tracks }
    db.playlistsByUser[userId] = list
    saveDb(db)
    sendJson(res, 200, { ok: true, playlist: list[idx] })
    return true
  }

  if (pathname === '/api/user/likes' && method === 'GET') {
    const userId = requireUser(req, res)
    if (!userId) return true
    sendJson(res, 200, { ok: true, likes: db.likesByUser[userId] || [] })
    return true
  }

  if (pathname === '/api/user/likes/toggle' && method === 'POST') {
    const userId = requireUser(req, res)
    if (!userId) return true
    const body = await jsonBody()
    const track = sanitizeTrack(body.track)
    if (!track) {
      sendJson(res, 400, { error: '参数错误' })
      return true
    }
    const list = Array.isArray(db.likesByUser[userId]) ? db.likesByUser[userId] : []
    const key = `${track.platform}:${track.id}`
    const idx = list.findIndex(t => t && `${t.platform}:${t.id}` === key)
    let liked = false
    if (idx >= 0) {
      list.splice(idx, 1)
      liked = false
    } else {
      list.unshift(track)
      liked = true
    }
    db.likesByUser[userId] = list.slice(0, 500)
    saveDb(db)
    sendJson(res, 200, { ok: true, liked, likes: db.likesByUser[userId] })
    return true
  }

  if (pathname === '/api/user/downloads' && method === 'GET') {
    const userId = requireUser(req, res)
    if (!userId) return true
    sendJson(res, 200, { ok: true, downloads: db.downloadsByUser[userId] || [] })
    return true
  }

  if (pathname === '/api/user/downloads/add' && method === 'POST') {
    const userId = requireUser(req, res)
    if (!userId) return true
    const body = await jsonBody()
    const track = sanitizeTrack(body.track)
    if (!track) {
      sendJson(res, 400, { error: '参数错误' })
      return true
    }
    const list = Array.isArray(db.downloadsByUser[userId]) ? db.downloadsByUser[userId] : []
    const key = `${track.platform}:${track.id}`
    const idx = list.findIndex(t => t && `${t.platform}:${t.id}` === key)
    if (idx >= 0) list.splice(idx, 1)
    list.unshift(track)
    db.downloadsByUser[userId] = list.slice(0, 500)
    saveDb(db)
    sendJson(res, 200, { ok: true, downloads: db.downloadsByUser[userId] })
    return true
  }

  if (pathname === '/api/user/recents' && method === 'GET') {
    const userId = requireUser(req, res)
    if (!userId) return true
    sendJson(res, 200, { ok: true, recents: db.recentsByUser[userId] || [] })
    return true
  }

  if (pathname === '/api/user/recents/add' && method === 'POST') {
    const userId = requireUser(req, res)
    if (!userId) return true
    const body = await jsonBody()
    const track = sanitizeTrack(body.track)
    if (!track) {
      sendJson(res, 400, { error: '参数错误' })
      return true
    }
    const list = Array.isArray(db.recentsByUser[userId]) ? db.recentsByUser[userId] : []
    const key = `${track.platform}:${track.id}`
    const idx = list.findIndex(t => t && `${t.platform}:${t.id}` === key)
    if (idx >= 0) list.splice(idx, 1)
    list.unshift(track)
    db.recentsByUser[userId] = list.slice(0, 200)
    saveDb(db)
    sendJson(res, 200, { ok: true, recents: db.recentsByUser[userId] })
    return true
  }

  sendJson(res, 404, { error: 'Not Found' })
  return true
}

function getContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase()
  switch (ext) {
    case '.html':
      return 'text/html; charset=utf-8'
    case '.js':
      return 'application/javascript; charset=utf-8'
    case '.css':
      return 'text/css; charset=utf-8'
    case '.svg':
      return 'image/svg+xml'
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg'
    case '.png':
      return 'image/png'
    case '.json':
      return 'application/json; charset=utf-8'
    case '.ico':
      return 'image/x-icon'
    default:
      return 'application/octet-stream'
  }
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(payload))
}

function isPrivateIp(ip) {
  if (!ip) return true
  if (ip === '127.0.0.1' || ip === '0.0.0.0') return true
  if (ip.startsWith('10.')) return true
  if (ip.startsWith('192.168.')) return true
  if (ip.startsWith('169.254.')) return true
  if (ip.startsWith('172.')) {
    const second = Number(ip.split('.')[1] || '')
    if (Number.isFinite(second) && second >= 16 && second <= 31) return true
  }
  return false
}

function sanitizeFilename(name) {
  const raw = String(name || '').trim() || 'music'
  const cleaned = raw.replace(/[\\/:*?"<>|\u0000-\u001F]/g, '_').replace(/\s+/g, ' ').trim()
  return (cleaned || 'music').slice(0, 180)
}

function proxyMedia(req, res) {
  const requestUrl = new URL(req.url, `http://${req.headers.host}`)
  if (requestUrl.pathname !== '/proxy') return false

  const targetRaw = requestUrl.searchParams.get('url') || ''
  if (!targetRaw) {
    sendJson(res, 400, { error: 'Missing url' })
    return true
  }

  let target
  try {
    target = new URL(targetRaw)
  } catch {
    sendJson(res, 400, { error: 'Invalid url' })
    return true
  }

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    sendJson(res, 400, { error: 'Unsupported protocol' })
    return true
  }

  if (!target.hostname || target.hostname === 'localhost') {
    sendJson(res, 403, { error: 'Forbidden' })
    return true
  }

  const ipType = net.isIP(target.hostname)
  if (ipType === 4 && isPrivateIp(target.hostname)) {
    sendJson(res, 403, { error: 'Forbidden' })
    return true
  }
  if (ipType === 6) {
    const h = target.hostname.toLowerCase()
    if (h === '::1' || h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) {
      sendJson(res, 403, { error: 'Forbidden' })
      return true
    }
  }

  const method = req.method || 'GET'
  if (method !== 'GET' && method !== 'HEAD') {
    sendJson(res, 405, { error: 'Method Not Allowed' })
    return true
  }

  const download = requestUrl.searchParams.get('download') === '1'
  const filename = sanitizeFilename(requestUrl.searchParams.get('filename') || 'music')

  const makeRequest = (urlObj, redirectCount) => {
    const transport = urlObj.protocol === 'https:' ? https : http
    const headers = {}
    if (req.headers.range) headers.range = req.headers.range
    if (req.headers['user-agent']) headers['user-agent'] = req.headers['user-agent']
    if (req.headers.accept) headers.accept = req.headers.accept
    if (req.headers['accept-language']) headers['accept-language'] = req.headers['accept-language']
    if (req.headers.referer) headers.referer = req.headers.referer

    const upstream = transport.request(
      urlObj,
      {
        method,
        headers,
      },
      upstreamRes => {
        const status = upstreamRes.statusCode || 502
        const location = upstreamRes.headers.location
        if (
          location &&
          [301, 302, 303, 307, 308].includes(status) &&
          redirectCount < 5
        ) {
          try {
            const nextUrl = new URL(location, urlObj)
            upstreamRes.resume()
            makeRequest(nextUrl, redirectCount + 1)
            return
          } catch {
            // fallthrough
          }
        }

        const outHeaders = { ...upstreamRes.headers }
        delete outHeaders['access-control-allow-origin']
        delete outHeaders['access-control-allow-credentials']
        delete outHeaders['access-control-allow-headers']
        delete outHeaders['access-control-allow-methods']
        outHeaders['access-control-allow-origin'] = '*'

        if (download) {
          outHeaders['content-disposition'] = `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`
        }

        res.writeHead(status, outHeaders)
        upstreamRes.pipe(res)
      },
    )

    upstream.on('error', err => {
      sendJson(res, 502, { error: 'Bad Gateway', message: err.message })
    })

    upstream.end()
  }

  makeRequest(target, 0)
  return true
}

function proxyRequest(req, res, target) {
  const requestUrl = new URL(req.url, `http://${req.headers.host}`)
  const upstreamPath = requestUrl.pathname.replace(target.stripPrefix, '') + requestUrl.search

  const upstream = http.request(
    {
      hostname: target.hostname,
      port: target.port,
      method: req.method,
      path: upstreamPath,
      headers: {
        ...req.headers,
        host: `${target.hostname}:${target.port}`,
      },
    },
    upstreamRes => {
      res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers)
      upstreamRes.pipe(res)
    },
  )

  upstream.on('error', err => {
    sendJson(res, 502, { error: 'Bad Gateway', message: err.message })
  })

  req.pipe(upstream)
}

async function proxyRequestWithFallback(req, res, targets) {
  if (!req.url) {
    sendJson(res, 400, { error: 'Bad Request' })
    return
  }

  const buffers = []
  for await (const chunk of req) buffers.push(chunk)
  const body = Buffer.concat(buffers)

  const requestUrl = new URL(req.url, `http://${req.headers.host}`)

  const tryOne = (index) =>
    new Promise(resolve => {
      const target = targets[index]
      if (!target) {
        sendJson(res, 502, { error: 'Bad Gateway', message: 'All upstreams failed' })
        resolve(true)
        return
      }

      const upstreamPath = requestUrl.pathname.replace(target.stripPrefix, '') + requestUrl.search
      const headers = {
        ...req.headers,
        host: `${target.hostname}:${target.port}`,
      }
      if (body.length > 0 && headers['content-length'] == null) headers['content-length'] = String(body.length)

      const upstream = http.request(
        {
          hostname: target.hostname,
          port: target.port,
          method: req.method,
          path: upstreamPath,
          headers,
        },
        upstreamRes => {
          const code = upstreamRes.statusCode || 502
          if (code === 404) {
            upstreamRes.resume()
            resolve(false)
            return
          }
          res.writeHead(code, upstreamRes.headers)
          upstreamRes.pipe(res)
          resolve(true)
        },
      )

      upstream.on('error', () => resolve(false))
      upstream.setTimeout(6000, () => upstream.destroy())
      upstream.end(body.length > 0 ? body : undefined)
    })

  for (let i = 0; i < targets.length; i += 1) {
    const ok = await tryOne(i)
    if (ok) return
  }

  sendJson(res, 502, { error: 'Bad Gateway', message: 'All upstreams failed' })
}

function serveStatic(req, res) {
  const requestUrl = new URL(req.url, `http://${req.headers.host}`)
  const rawPathname = decodeURIComponent(requestUrl.pathname)
  const adminRoutes = new Set(['/admin', '/admin/'])
  const appRoutes = new Set([
    '/',
    '/recommend',
    '/radio',
    '/playlist-square',
    '/playlists',
    '/hot',
    '/charts',
    '/artists',
    '/favorites',
    '/downloads',
    '/recent',
    '/player',
    '/login',
  ])
  const pathname = adminRoutes.has(rawPathname) ? '/admin.html' : appRoutes.has(rawPathname) ? '/index.html' : rawPathname

  const safePath = path
    .normalize(pathname)
    .replace(/^(\.\.[/\\])+/, '')
    .replace(/^[\\/]+/, '')
  const filePath = path.join(ROOT_DIR, safePath)

  if (!filePath.startsWith(ROOT_DIR)) {
    sendJson(res, 403, { error: 'Forbidden' })
    return
  }

  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('Not Found')
      return
    }

    res.writeHead(200, { 'Content-Type': getContentType(filePath) })
    fs.createReadStream(filePath).pipe(res)
  })
}

http
  .createServer(async (req, res) => {
    if (!req.url) {
      sendJson(res, 400, { error: 'Bad Request' })
      return
    }

    if (req.url.startsWith('/api/')) {
      const handled = await handleApi(req, res)
      if (handled) return
    }

    if (req.url.startsWith('/proxy')) {
      if (proxyMedia(req, res)) return
    }

    if (req.url.startsWith('/kugou')) {
      await ensureKugouApiReady()
      const current = parseCookies(req.headers.cookie)
      const db = loadDb()
      await ensureKugouAuthReady(db)
      const authJar = pickKugouAuthCookieJar(db.kugouAuth)
      if (authJar.token && authJar.userid) {
        const merged = { ...current, ...authJar }
        req.headers.cookie = buildCookieHeader(merged)
      }
      await proxyRequestWithFallback(req, res, [
        ...KUGOU_UPSTREAMS,
      ])
      return
    }

    if (req.url.startsWith('/netease')) {
      proxyRequest(req, res, { hostname: NETEASE_HOST, port: NETEASE_PORT, stripPrefix: '/netease' })
      return
    }

    serveStatic(req, res)
  })
  .listen(PORT, '0.0.0.0', () => {
    console.log(`Magic Music server running at http://localhost:${PORT}`)
    ensureKugouApiReady().catch(() => {})
  })
