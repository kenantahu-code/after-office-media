const crypto = require('crypto');

const API_BASE = 'https://open.tiktokapis.com';
const AUTH_URL = 'https://www.tiktok.com/v2/auth/authorize/';
const VERIFIED_PREFIX = process.env.TIKTOK_VERIFIED_MEDIA_PREFIX || 'https://kenantahu-code.github.io/after-office-media/';
const ENVIRONMENT = (process.env.TIKTOK_ENVIRONMENT || 'sandbox').toLowerCase();

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.setHeader('Cache-Control', 'no-store');
  res.end();
}

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function sessionKey() {
  return crypto.createHash('sha256').update(required('SESSION_SECRET')).digest();
}

function seal(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey(), iv);
  const plain = Buffer.from(JSON.stringify(obj), 'utf8');
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ['v1', iv.toString('base64url'), tag.toString('base64url'), enc.toString('base64url')].join('.');
}

function unseal(value) {
  const [version, ivB64, tagB64, encB64] = String(value || '').split('.');
  if (version !== 'v1' || !ivB64 || !tagB64 || !encB64) throw new Error('Invalid session');
  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey(), Buffer.from(ivB64, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(encB64, 'base64url')),
    decipher.final(),
  ]);
  return JSON.parse(plain.toString('utf8'));
}

async function tiktokForm(path, form) {
  const r = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`TikTok HTTP ${r.status}: ${JSON.stringify(data)}`);
  if (data.error && data.error.code && data.error.code !== 'ok') {
    throw new Error(`${data.error.code}: ${data.error.message || ''}`);
  }
  if (data.error && typeof data.error === 'string') {
    throw new Error(`${data.error}: ${data.error_description || ''}`);
  }
  return data;
}

async function tiktokJson(path, accessToken, payload) {
  const r = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json; charset=UTF-8',
    },
    body: JSON.stringify(payload),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`TikTok HTTP ${r.status}: ${JSON.stringify(data)}`);
  if (data.error && data.error.code && data.error.code !== 'ok') {
    throw new Error(`${data.error.code}: ${data.error.message || ''}`);
  }
  return data;
}

function setSession(res, session) {
  res.setHeader('Set-Cookie', cookie('ao_tiktok_session', seal(session), 60 * 60 * 24 * 30));
}

async function loadSession(req, res) {
  const cookies = parseCookies(req.headers.cookie || '');
  if (!cookies.ao_tiktok_session) return null;
  let session = unseal(cookies.ao_tiktok_session);
  const now = Date.now();
  if (!session.access_token || !session.refresh_token) return null;
  if (!session.access_expires_at || session.access_expires_at < now + 5 * 60 * 1000) {
    const refreshed = await tiktokForm('/v2/oauth/token/', {
      client_key: required('TIKTOK_CLIENT_KEY'),
      client_secret: required('TIKTOK_CLIENT_SECRET'),
      grant_type: 'refresh_token',
      refresh_token: session.refresh_token,
    });
    session = {
      ...session,
      access_token: refreshed.access_token,
      refresh_token: refreshed.refresh_token || session.refresh_token,
      scope: refreshed.scope || session.scope,
      access_expires_at: now + Number(refreshed.expires_in || 86400) * 1000,
      refresh_expires_at: now + Number(refreshed.refresh_expires_in || 31536000) * 1000,
    };
    setSession(res, session);
  }
  return session;
}

async function queryCreator(accessToken) {
  const response = await tiktokJson('/v2/post/publish/creator_info/query/', accessToken, {});
  if (!response.data) throw new Error('creator_info returned no data');
  return response.data;
}

function bodyObject(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  try { return JSON.parse(req.body); } catch { return {}; }
}

async function handleStart(req, res) {
  const state = crypto.randomBytes(24).toString('hex');
  const redirectUri = required('TIKTOK_REDIRECT_URI');
  const params = new URLSearchParams({
    client_key: required('TIKTOK_CLIENT_KEY'),
    response_type: 'code',
    scope: 'user.info.basic,video.publish',
    redirect_uri: redirectUri,
    state,
    disable_auto_auth: '1',
  });
  res.setHeader('Set-Cookie', cookie('ao_tiktok_oauth_state', state, 600));
  redirect(res, `${AUTH_URL}?${params.toString()}`);
}

async function handleCallback(req, res) {
  if (req.query.error) {
    return redirect(res, `/app.html?oauth_error=${encodeURIComponent(req.query.error_description || req.query.error)}`);
  }
  const cookies = parseCookies(req.headers.cookie || '');
  if (!req.query.code || !req.query.state || !cookies.ao_tiktok_oauth_state || req.query.state !== cookies.ao_tiktok_oauth_state) {
    return redirect(res, '/app.html?oauth_error=invalid_state');
  }
  const token = await tiktokForm('/v2/oauth/token/', {
    client_key: required('TIKTOK_CLIENT_KEY'),
    client_secret: required('TIKTOK_CLIENT_SECRET'),
    code: req.query.code,
    grant_type: 'authorization_code',
    redirect_uri: required('TIKTOK_REDIRECT_URI'),
  });
  const now = Date.now();
  const session = {
    access_token: token.access_token,
    refresh_token: token.refresh_token,
    open_id: token.open_id,
    scope: token.scope,
    access_expires_at: now + Number(token.expires_in || 86400) * 1000,
    refresh_expires_at: now + Number(token.refresh_expires_in || 31536000) * 1000,
  };
  res.setHeader('Set-Cookie', [
    cookie('ao_tiktok_session', seal(session), 60 * 60 * 24 * 30),
    cookie('ao_tiktok_oauth_state', '', 0),
  ]);
  redirect(res, '/app.html?connected=1');
}

async function handleCreator(req, res) {
  const session = await loadSession(req, res);
  if (!session) return json(res, 401, { connected: false });
  const creator = await queryCreator(session.access_token);
  const options = Array.isArray(creator.privacy_level_options) ? creator.privacy_level_options : [];
  const privacy = ENVIRONMENT === 'production' ? options : options.filter(x => x === 'SELF_ONLY');
  return json(res, 200, {
    connected: true,
    creator_username: creator.creator_username,
    creator_nickname: creator.creator_nickname,
    privacy_level_options: privacy,
    comment_disabled: Boolean(creator.comment_disabled),
    environment: ENVIRONMENT,
  });
}

function validateMedia(urls) {
  if (!Array.isArray(urls) || urls.length < 1 || urls.length > 35) throw new Error('Photo post must contain 1-35 image URLs.');
  for (const url of urls) {
    if (typeof url !== 'string' || !url.startsWith('https://')) throw new Error('All media URLs must use HTTPS.');
    if (!url.startsWith(VERIFIED_PREFIX)) throw new Error(`Media URL must be under verified prefix: ${VERIFIED_PREFIX}`);
  }
}

async function handlePublish(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'POST required' });
  const session = await loadSession(req, res);
  if (!session) return json(res, 401, { error: 'Connect TikTok first.' });
  const body = bodyObject(req);
  if (body.consent !== true) return json(res, 400, { error: 'Explicit publishing consent is required.' });
  const title = String(body.title || '');
  const description = String(body.description || '');
  if (title.length > 90) return json(res, 400, { error: 'Title must be 90 characters or fewer.' });
  if (description.length > 4000) return json(res, 400, { error: 'Description must be 4000 characters or fewer.' });
  const mediaUrls = Array.isArray(body.media_urls) ? body.media_urls : [];
  try { validateMedia(mediaUrls); } catch (e) { return json(res, 400, { error: e.message }); }

  const creator = await queryCreator(session.access_token);
  const privacy = String(body.privacy_level || '');
  if (!privacy) return json(res, 400, { error: 'Select a privacy option before publishing.' });
  if (body.brand_content_toggle === true && privacy === 'SELF_ONLY') return json(res, 400, { error: 'Branded content visibility cannot be private.' });
  const options = Array.isArray(creator.privacy_level_options) ? creator.privacy_level_options : [];
  if (!options.includes(privacy)) return json(res, 400, { error: `Privacy option is not available for this creator: ${privacy}` });
  if (ENVIRONMENT !== 'production' && privacy !== 'SELF_ONLY') {
    return json(res, 400, { error: 'Sandbox/unaudited mode requires SELF_ONLY.' });
  }
  if (body.disable_comment === false && creator.comment_disabled) {
    return json(res, 400, { error: 'Comments are disabled in the connected creator settings.' });
  }

  const payload = {
    post_info: {
      title,
      description,
      privacy_level: privacy,
      disable_comment: Boolean(body.disable_comment),
      auto_add_music: body.auto_add_music !== false,
      brand_content_toggle: Boolean(body.brand_content_toggle),
      brand_organic_toggle: Boolean(body.brand_organic_toggle),
    },
    source_info: {
      source: 'PULL_FROM_URL',
      photo_cover_index: Number.isInteger(body.photo_cover_index) ? body.photo_cover_index : 0,
      photo_images: mediaUrls,
    },
    post_mode: 'DIRECT_POST',
    media_type: 'PHOTO',
    is_aigc: Boolean(body.is_aigc),
  };
  const response = await tiktokJson('/v2/post/publish/content/init/', session.access_token, payload);
  const publishId = response.data && response.data.publish_id;
  if (!publishId) throw new Error('TikTok did not return publish_id.');
  return json(res, 200, { ok: true, publish_id: publishId });
}

async function handleStatus(req, res) {
  const session = await loadSession(req, res);
  if (!session) return json(res, 401, { error: 'Connect TikTok first.' });
  const publishId = String(req.query.publish_id || '');
  if (!publishId) return json(res, 400, { error: 'publish_id is required.' });
  const response = await tiktokJson('/v2/post/publish/status/fetch/', session.access_token, { publish_id: publishId });
  return json(res, 200, { ok: true, data: response.data || {} });
}

async function handleLogout(req, res) {
  res.setHeader('Set-Cookie', cookie('ao_tiktok_session', '', 0));
  redirect(res, '/app.html?logged_out=1');
}

module.exports = async function handler(req, res) {
  try {
    const action = String(req.query.action || '');
    if (action === 'start') return await handleStart(req, res);
    if (action === 'callback') return await handleCallback(req, res);
    if (action === 'creator') return await handleCreator(req, res);
    if (action === 'publish') return await handlePublish(req, res);
    if (action === 'status') return await handleStatus(req, res);
    if (action === 'logout') return await handleLogout(req, res);
    return json(res, 404, { error: 'Unknown action.' });
  } catch (error) {
    console.error('After Office Publisher TikTok API error:', error && error.stack ? error.stack : error);
    return json(res, 500, { error: error && error.message ? error.message : 'Unexpected server error.' });
  }
};
