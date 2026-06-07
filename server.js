/* ─────────────────────────────────────────────────────────────────────────
   TIINDA — Backend (Twilio Verify + Supabase)
   ─────────────────────────────────────────────────────────────────────────
   Rôle :
     1) Vérifier les numéros par WhatsApp/SMS (Twilio Verify).
     2) Stocker les vraies données dans Supabase : clients, colis, recharges.

   Routes :
     POST /send            { phone }                         → envoie le code
     POST /verify          { phone, code, prenom, nom, ... } → vérifie le code,
                                                               crée le client,
                                                               renvoie ses infos
     GET  /client          ?phone=...                        → récupère un client
     POST /colis/declare   { phone, description, ... }       → déclare un colis
     GET  /colis           ?phone=...                        → liste les colis
     GET  /health                                            → { ok: true }

   ⚠️  Clés secrètes (Twilio + Supabase) UNIQUEMENT dans les variables
       d'environnement de ce serveur — jamais dans le thème Shopify.
   ───────────────────────────────────────────────────────────────────────── */

const express = require('express');
const crypto  = require('crypto');
const twilio  = require('twilio');
const { createClient } = require('@supabase/supabase-js');

const {
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_VERIFY_SERVICE_SID,   // SID du Verify Service (commence par "VA...")
  SHOPIFY_API_SECRET,          // "API secret key" de ton app Shopify (signe le proxy)
  SUPABASE_URL,                // https://xxxx.supabase.co
  SUPABASE_SERVICE_KEY,        // clé secrète Supabase (sb_secret_...)
  RESEND_API_KEY,              // clé API Resend (envoi d'emails) — optionnel
  MAIL_FROM,                   // expéditeur, ex: "Tiinda <noreply@tiinda.com>"
  TRACK123_API_KEY,            // clé API Track123 (suivi colis) — optionnel
  ADMIN_TOKEN,                 // mot de passe du panneau Admin Tiinda
  SESSION_SECRET,              // secret pour signer les tokens de session client
  ALLOWED_ORIGINS,             // domaines autorisés (CORS), séparés par des virgules
  PORT = 3000,
} = process.env;

const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

// Connexion Supabase (uniquement si les clés sont présentes — évite un crash).
const db = (SUPABASE_URL && SUPABASE_SERVICE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
  : null;

const app = express();
app.use(express.json());
app.set('trust proxy', true);

/* ── 0) CORS — restreint aux domaines Tiinda (plus de '*' ouvert à tous) ─────
   On autorise : la liste ALLOWED_ORIGINS (env), tiinda.com / www.tiinda.com par
   défaut, et tout sous-domaine *.myshopify.com (preview/boutique Shopify).
   Le token de session reste la vraie barrière d'authentification ; le CORS
   réduit la surface d'abus depuis d'autres sites. */
const CORS_LIST = (ALLOWED_ORIGINS || 'https://tiinda.com,https://www.tiinda.com')
  .split(',').map(function (s) { return s.trim(); }).filter(Boolean);
function originAllowed(origin) {
  if (!origin) return false;
  if (CORS_LIST.indexOf(origin) >= 0) return true;
  try { var h = new URL(origin).hostname; return /\.myshopify\.com$/.test(h) || h === 'tiinda.com' || h === 'www.tiinda.com'; }
  catch (e) { return false; }
}
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (originAllowed(origin)) { res.header('Access-Control-Allow-Origin', origin); res.header('Vary', 'Origin'); }
  res.header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-admin-token, x-scan-token');
  res.header('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

/* ── 0b) TOKENS DE SESSION CLIENT (HMAC, sans librairie externe) ────────────
   Après un OTP valide, on émet un token signé contenant le téléphone + une
   expiration. Les routes client en déduisent le téléphone — on ne fait JAMAIS
   confiance à un ?phone= brut. */
const SESSION_KEY = SESSION_SECRET
  || (SUPABASE_SERVICE_KEY ? crypto.createHash('sha256').update('tiinda::' + SUPABASE_SERVICE_KEY).digest('hex') : 'dev-secret-change-me');
const SESSION_TTL_MS = 30 * 86400000; // 30 jours
function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function signSession(phone) {
  const payload = b64url(JSON.stringify({ p: phone, exp: Date.now() + SESSION_TTL_MS }));
  const sig = b64url(crypto.createHmac('sha256', SESSION_KEY).update(payload).digest());
  return payload + '.' + sig;
}
function verifySession(tokenRaw) {
  if (!tokenRaw || typeof tokenRaw !== 'string' || tokenRaw.indexOf('.') < 0) return null;
  const parts = tokenRaw.split('.');
  const expected = b64url(crypto.createHmac('sha256', SESSION_KEY).update(parts[0]).digest());
  if (!parts[1] || parts[1].length !== expected.length) return null;
  try { if (!crypto.timingSafeEqual(Buffer.from(parts[1]), Buffer.from(expected))) return null; } catch (e) { return null; }
  let data; try { data = JSON.parse(Buffer.from(parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); } catch (e) { return null; }
  if (!data || !data.p || !data.exp || Date.now() > data.exp) return null;
  return data.p;
}
// Middleware : exige un token de session valide ; expose req.clientPhone.
function requireAuth(req, res, next) {
  const h = req.headers['authorization'] || '';
  const token = h.indexOf('Bearer ') === 0 ? h.slice(7) : (req.query.token || (req.body && req.body.token));
  const phone = verifySession(token);
  if (!phone) return res.status(401).json({ ok: false, error: 'unauthenticated' });
  req.clientPhone = phone;
  next();
}

/* ── Hachage de mot de passe (pbkdf2, sans librairie externe) ───────────── */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(String(pw), salt, 120000, 32, 'sha256').toString('hex');
  return 'pbkdf2$120000$' + salt + '$' + hash;
}
function verifyPassword(pw, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iter = parseInt(parts[1], 10), salt = parts[2], expected = parts[3];
  const hash = crypto.pbkdf2Sync(String(pw), salt, iter, 32, 'sha256').toString('hex');
  try { return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(expected)); } catch (e) { return false; }
}

/* ── Jetons de réinitialisation de mot de passe (signés, courte durée) ──────
   Contient l'email + une expiration (1h). Envoyé par email uniquement. */
const RESET_TTL_MS = 60 * 60000; // 1 heure
function signReset(email) {
  const payload = b64url(JSON.stringify({ e: email, exp: Date.now() + RESET_TTL_MS, t: 'reset' }));
  const sig = b64url(crypto.createHmac('sha256', SESSION_KEY).update('reset:' + payload).digest());
  return payload + '.' + sig;
}
function verifyReset(tokenRaw) {
  if (!tokenRaw || typeof tokenRaw !== 'string' || tokenRaw.indexOf('.') < 0) return null;
  const parts = tokenRaw.split('.');
  const expected = b64url(crypto.createHmac('sha256', SESSION_KEY).update('reset:' + parts[0]).digest());
  if (!parts[1] || parts[1].length !== expected.length) return null;
  try { if (!crypto.timingSafeEqual(Buffer.from(parts[1]), Buffer.from(expected))) return null; } catch (e) { return null; }
  let data; try { data = JSON.parse(Buffer.from(parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); } catch (e) { return null; }
  if (!data || !data.e || data.t !== 'reset' || !data.exp || Date.now() > data.exp) return null;
  return data.e;
}

/* ── 0c) RATE LIMITING simple en mémoire (anti-abus / anti-brute force) ───── */
const rateBuckets = new Map();
function clientIp(req) { return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || 'unknown'; }
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const arr = (rateBuckets.get(key) || []).filter(function (t) { return now - t < windowMs; });
  if (arr.length >= max) { rateBuckets.set(key, arr); return false; }
  arr.push(now); rateBuckets.set(key, arr); return true;
}
setInterval(function () { // purge périodique des compteurs expirés
  const now = Date.now();
  rateBuckets.forEach(function (arr, k) { const f = arr.filter(function (t) { return now - t < 3600000; }); if (f.length) rateBuckets.set(k, f); else rateBuckets.delete(k); });
}, 600000);

/* ── 1) Vérification de la signature Shopify App Proxy ─────────────────────
   (court-circuitée avec SKIP_PROXY_CHECK=1 quand on appelle le backend en
    direct, sans passer par l'App Proxy Shopify.) */
function verifyShopifyProxy(req, res, next) {
  if (process.env.SKIP_PROXY_CHECK === '1') return next();
  const { signature, ...params } = req.query;
  if (!signature) return res.status(401).json({ ok: false, error: 'missing signature' });
  const message = Object.keys(params).sort().map((key) => {
    const value = Array.isArray(params[key]) ? params[key].join(',') : params[key];
    return `${key}=${value}`;
  }).join('');
  const digest = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(message).digest('hex');
  const ok = digest.length === String(signature).length &&
    crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(String(signature)));
  if (!ok) return res.status(401).json({ ok: false, error: 'invalid signature' });
  next();
}

/* ── 2) Normalisation du numéro au format E.164 ─────────────────────────── */
function toE164(phone) {
  if (!phone) return '';
  const digits = String(phone).trim().replace(/\D/g, '');
  return '+' + digits;
}

/* ── 3) Génère le PROCHAIN identifiant TIINDA (ex : TIINDA000248) ──────────
   On lit le dernier identifiant existant, on prend son numéro et on l'incrémente.
   La numérotation démarre à 248 (pour continuer après la maquette). */
async function nextTiindaId() {
  const START = 248;
  if (!db) return 'TIINDA' + String(START).padStart(6, '0');
  const { data } = await db
    .from('clients')
    .select('tiinda_id')
    .order('created_at', { ascending: false })
    .limit(50);
  let max = START - 1;
  (data || []).forEach((row) => {
    const n = parseInt(String(row.tiinda_id || '').replace(/\D/g, ''), 10);
    if (!isNaN(n) && n > max) max = n;
  });
  return 'TIINDA' + String(max + 1).padStart(6, '0');
}

/* Récupère un client par téléphone, ou le crée s'il n'existe pas encore. */
async function getOrCreateClient(phone, info = {}) {
  if (!db) return null;
  // Déjà existant ?
  const { data: existing } = await db
    .from('clients').select('*').eq('phone', phone).limit(1).maybeSingle();
  if (existing) return existing;
  // Sinon on le crée avec un identifiant unique.
  const tiinda_id = await nextTiindaId();
  const insert = {
    tiinda_id,
    prenom: info.prenom || null,
    nom:    info.nom || null,
    email:  info.email ? String(info.email).trim().toLowerCase() : null,
    phone,
    ville:  info.ville || null,
    offre:  info.offre || null,
  };
  // Mot de passe (pour la connexion email + mot de passe).
  if (info.password) insert.password_hash = hashPassword(info.password);
  // Parrainage : si un code parrain valide est fourni, on le relie.
  if (info.ref) {
    const refCode = String(info.ref).trim().toUpperCase();
    const { data: parrain } = await db.from('clients').select('id').eq('tiinda_id', refCode).limit(1).maybeSingle();
    if (parrain) insert.parrain_id = parrain.id;
  }
  const { data: created, error } = await db.from('clients').insert(insert).select().single();
  if (error) { console.error('create client error:', error.message); return null; }
  return created;
}

/* ── 4) Route : envoi du code (WhatsApp ou SMS selon OTP_CHANNEL) ────────── */
app.post('/send', verifyShopifyProxy, async (req, res) => {
  try {
    if (!rateLimit('send:' + clientIp(req), 8, 600000)) return res.status(429).json({ ok: false, error: 'too_many_requests' });
    const phone = toE164(req.body.phone);
    if (!phone || phone.length < 8) return res.status(400).json({ ok: false, error: 'invalid phone' });
    await client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({ to: phone, channel: process.env.OTP_CHANNEL || 'whatsapp' });
    res.json({ ok: true });
  } catch (err) {
    console.error('send error:', err.message);
    res.status(500).json({ ok: false, error: 'send_failed' });
  }
});

/* ── 5) Route : vérification du code + création du client dans Supabase ──── */
app.post('/verify', verifyShopifyProxy, async (req, res) => {
  try {
    if (!rateLimit('verify:' + clientIp(req), 20, 600000)) return res.status(429).json({ ok: false, error: 'too_many_requests' });
    const phone = toE164(req.body.phone);
    const code = String(req.body.code || '').replace(/\D/g, '');
    if (!phone || code.length !== 6) return res.status(400).json({ ok: false, error: 'invalid_input' });

    const check = await client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({ to: phone, code });
    const approved = check.status === 'approved';
    if (!approved) return res.json({ ok: false });

    // ✅ Code validé → on crée (ou récupère) le client dans Supabase.
    const record = await getOrCreateClient(phone, {
      prenom: req.body.prenom,
      nom:    req.body.nom,
      email:  req.body.email,
      ville:  req.body.ville,
      offre:  req.body.offre,
      password: req.body.password,
      ref: req.body.ref,
    });

    res.json({
      ok: true,
      token: signSession(phone),   // ← token de session signé (à stocker côté client)
      client: record ? {
        tiinda_id: record.tiinda_id,
        prenom: record.prenom, nom: record.nom,
        email: record.email, phone: record.phone, ville: record.ville,
        offre: record.offre, wallet_balance: record.wallet_balance,
      } : null,
    });
  } catch (err) {
    console.error('verify error:', err.message);
    res.status(200).json({ ok: false, error: 'verify_failed' });
  }
});

/* ── Route : connexion par EMAIL + MOT DE PASSE ────────────────────────────
   Le téléphone reste réservé à l'inscription (collecte des vrais numéros).
   Retourne un token de session signé + les infos du client. */
app.post('/login', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    if (!rateLimit('login:' + clientIp(req), 12, 600000)) return res.status(429).json({ ok: false, error: 'too_many_requests' });
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!email || !password) return res.json({ ok: false, error: 'missing' });
    const { data: cli } = await db.from('clients').select('*').ilike('email', email).limit(1).maybeSingle();
    // Message générique (ne révèle pas si l'email existe) pour la sécurité.
    if (!cli || !cli.password_hash || !verifyPassword(password, cli.password_hash)) {
      return res.json({ ok: false, error: 'invalid_credentials' });
    }
    res.json({
      ok: true,
      token: signSession(cli.phone),
      client: {
        tiinda_id: cli.tiinda_id, prenom: cli.prenom, nom: cli.nom,
        email: cli.email, phone: cli.phone, ville: cli.ville,
        offre: cli.offre, wallet_balance: cli.wallet_balance,
      },
    });
  } catch (err) {
    console.error('login error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ── Mot de passe oublié : envoi d'un lien de réinitialisation par EMAIL ────
   Réponse toujours générique (on ne révèle pas si l'email existe). */
app.post('/password/forgot', async (req, res) => {
  try {
    if (!db) return res.json({ ok: true });
    if (!rateLimit('forgot:' + clientIp(req), 6, 600000)) return res.status(429).json({ ok: false, error: 'too_many_requests' });
    const email = String(req.body.email || '').trim().toLowerCase();
    if (email) {
      const { data: cli } = await db.from('clients').select('id, prenom, email').ilike('email', email).limit(1).maybeSingle();
      if (cli && cli.email && RESEND_API_KEY) {
        const tokenR = signReset(cli.email);
        const base = (process.env.SITE_URL || 'https://tiinda.com');
        const link = base + '/pages/reinitialiser-mot-de-passe?token=' + encodeURIComponent(tokenR);
        const html =
          '<div style="font-family:Arial,Helvetica,sans-serif;max-width:520px;margin:auto;color:#1a1a1a">' +
            '<div style="background:#0057FF;color:#fff;padding:20px;border-radius:12px 12px 0 0;text-align:center">' +
              '<div style="font-size:21px;font-weight:800">TIINDA</div><div style="font-size:13px;opacity:.85">Réinitialisation du mot de passe</div></div>' +
            '<div style="border:1px solid #eee;border-top:none;padding:24px;border-radius:0 0 12px 12px">' +
              '<p>Bonjour ' + (cli.prenom || '') + ',</p>' +
              '<p>Vous avez demandé à réinitialiser votre mot de passe Tiinda. Cliquez sur le bouton ci-dessous (lien valable 1&nbsp;heure) :</p>' +
              '<p style="text-align:center;margin:24px 0"><a href="' + link + '" style="background:#0057FF;color:#fff;text-decoration:none;padding:13px 26px;border-radius:10px;font-weight:700;display:inline-block">Définir un nouveau mot de passe</a></p>' +
              '<p style="font-size:12.5px;color:#666">Si vous n\u2019êtes pas à l\u2019origine de cette demande, ignorez cet email : votre mot de passe restera inchangé.</p>' +
              '<p style="font-size:12px;color:#999;word-break:break-all">Ou copiez ce lien : ' + link + '</p>' +
            '</div></div>';
        try {
          await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({ from: MAIL_FROM || 'Tiinda <onboarding@resend.dev>', to: cli.email, subject: 'Tiinda — Réinitialisation de votre mot de passe', html }),
          });
        } catch (e) { console.error('forgot mail error:', e.message); }
      }
    }
    res.json({ ok: true }); // toujours générique
  } catch (err) {
    console.error('forgot error:', err.message);
    res.json({ ok: true });
  }
});

/* ── Réinitialisation effective : token (du lien email) + nouveau mot de passe */
app.post('/password/reset', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    if (!rateLimit('reset:' + clientIp(req), 12, 600000)) return res.status(429).json({ ok: false, error: 'too_many_requests' });
    const email = verifyReset(req.body.token);
    const password = String(req.body.password || '');
    if (!email) return res.json({ ok: false, error: 'lien_invalide' });
    if (password.length < 8) return res.json({ ok: false, error: 'mot_de_passe_court' });
    const { data: cli } = await db.from('clients').select('id, prenom, email').ilike('email', email).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'compte_introuvable' });
    const newHash = hashPassword(password);
    // Met à jour TOUTES les lignes de cet email (au cas où des doublons existent),
    // pour que la connexion fonctionne quelle que soit la ligne lue ensuite.
    await db.from('clients').update({ password_hash: newHash }).ilike('email', email);
    // Email de confirmation (ne bloque pas la réponse).
    if (RESEND_API_KEY && cli.email) {
      const html =
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:520px;margin:auto;color:#1a1a1a">' +
          '<div style="background:#0057FF;color:#fff;padding:20px;border-radius:12px 12px 0 0;text-align:center">' +
            '<div style="font-size:21px;font-weight:800">TIINDA</div><div style="font-size:13px;opacity:.85">Mot de passe modifié</div></div>' +
          '<div style="border:1px solid #eee;border-top:none;padding:24px;border-radius:0 0 12px 12px">' +
            '<p>Bonjour ' + (cli.prenom || '') + ',</p>' +
            '<p>✅ Votre mot de passe Tiinda vient d\u2019être <strong>modifié avec succès</strong>.</p>' +
            '<p>Vous pouvez désormais vous connecter avec votre nouveau mot de passe.</p>' +
            '<p style="font-size:12.5px;color:#666">Si vous n\u2019êtes pas à l\u2019origine de ce changement, contactez-nous immédiatement via l\u2019assistance WhatsApp.</p>' +
            '<p style="margin-top:18px">L\u2019équipe Tiinda</p>' +
          '</div></div>';
      try {
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
          body: JSON.stringify({ from: MAIL_FROM || 'Tiinda <onboarding@resend.dev>', to: cli.email, subject: 'Tiinda — Votre mot de passe a été modifié ✓', html }),
        });
      } catch (e) { console.error('reset confirm mail error:', e.message); }
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('reset error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ── 6) Route : récupérer un client par téléphone (pour la connexion) ────── */
app.get('/client', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const phone = req.clientPhone;
    const { data } = await db.from('clients').select('*').eq('phone', phone).limit(1).maybeSingle();
    if (!data) return res.json({ ok: false, error: 'not_found' });
    res.json({ ok: true, client: {
      tiinda_id: data.tiinda_id, prenom: data.prenom, nom: data.nom,
      email: data.email, phone: data.phone, ville: data.ville,
      offre: data.offre, wallet_balance: data.wallet_balance,
      naissance: data.naissance, genre: data.genre,
      commune: data.commune, rue: data.rue, repere: data.repere,
    }});
  } catch (err) {
    console.error('client error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ── Envoi d'un email de confirmation via Resend (si la clé est configurée).
   N'installe aucune librairie : simple appel HTTP. Si RESEND_API_KEY n'est
   pas défini, la fonction ne fait rien (pas d'erreur). ───────────────────── */
async function sendDeclarationEmail(client, colis) {
  if (!RESEND_API_KEY || !client || !client.email) return;
  const from = MAIL_FROM || 'Tiinda <onboarding@resend.dev>';
  const prenom = client.prenom || 'cher client';
  const euro = colis.valeur != null ? (' (' + colis.valeur + ' €)') : '';
  const html =
    '<div style="font-family:Arial,Helvetica,sans-serif;max-width:520px;margin:auto;color:#1a1a1a">' +
      '<div style="background:#0057FF;color:#fff;padding:22px;border-radius:12px 12px 0 0;text-align:center">' +
        '<div style="font-size:22px;font-weight:800;letter-spacing:.5px">TIINDA</div>' +
        '<div style="font-size:13px;opacity:.85;margin-top:2px">Colis déclaré ✓</div></div>' +
      '<div style="border:1px solid #eee;border-top:none;padding:22px;border-radius:0 0 12px 12px">' +
        '<p>Bonjour ' + prenom + ',</p>' +
        '<p>Votre colis a bien été enregistré. Voici le récapitulatif :</p>' +
        '<table style="width:100%;border-collapse:collapse;font-size:14px;margin:14px 0">' +
          '<tr><td style="padding:8px 0;color:#666">N° de suivi Tiinda</td><td style="padding:8px 0;font-weight:bold;text-align:right;color:#0057FF">' + colis.tracking_interne + '</td></tr>' +
          '<tr><td style="padding:8px 0;color:#666">Suivi transporteur</td><td style="padding:8px 0;text-align:right">' + (colis.tracking_externe || '—') + '</td></tr>' +
          '<tr><td style="padding:8px 0;color:#666">Description</td><td style="padding:8px 0;text-align:right">' + (colis.description || '—') + '</td></tr>' +
          '<tr><td style="padding:8px 0;color:#666">Site marchand</td><td style="padding:8px 0;text-align:right">' + (colis.site_marchand || '—') + '</td></tr>' +
          '<tr><td style="padding:8px 0;color:#666">Valeur déclarée</td><td style="padding:8px 0;text-align:right">' + (colis.valeur != null ? colis.valeur + ' €' : '—') + '</td></tr>' +
        '</table>' +
        '<div style="text-align:center;background:#F5F8FF;border:1px solid #E1EAFF;border-radius:12px;padding:18px;margin:18px 0">' +
          '<img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&margin=0&data=' + encodeURIComponent(colis.tracking_interne) + '" alt="QR de retrait" width="160" height="160" style="background:#fff;border-radius:10px;padding:8px" />' +
          '<div style="font-size:13px;color:#444;margin-top:10px"><strong>QR de retrait</strong> — présentez-le pour récupérer votre colis dans un casier ou point relais Tiinda au Congo.</div>' +
        '</div>' +
        '<p style="font-size:13px;color:#666">Vous serez notifié sur WhatsApp dès la réception de votre colis à notre entrepôt. Conservez votre numéro de suivi Tiinda pour le retrait au Congo.</p>' +
        '<p style="margin-top:18px">L’équipe Tiinda</p>' +
      '</div>' +
      '<div style="text-align:center;color:#999;font-size:11px;padding:14px">Tiinda — une marque de Colispo · France · Congo-Brazzaville &amp; RDC</div>' +
    '</div>';
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: client.email, subject: 'Tiinda — Colis déclaré (' + colis.tracking_interne + ')' + euro, html }),
    });
    if (!r.ok) console.error('email error:', r.status, await r.text());
  } catch (e) { console.error('email send error:', e.message); }
}

/* ── 7) Route : déclarer un colis ─────────────────────────────────────────
   Génère un numéro de suivi interne unique (TND + horodatage). */
app.post('/colis/declare', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const phone = req.clientPhone;
    const { data: cli } = await db.from('clients').select('id, email, prenom, tiinda_id, parrain_id').eq('phone', phone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'client_not_found' });

    const tracking_interne = 'TND' + Date.now().toString().slice(-9);
    const { data, error } = await db.from('colis').insert({
      client_id: cli.id,
      tracking_interne,
      tracking_externe: req.body.tracking_externe || null,
      description: req.body.description || null,
      site_marchand: req.body.site_marchand || null,
      valeur: req.body.valeur || null,
      statut: 'declare',
    }).select().single();
    if (error) { console.error('colis error:', error.message); return res.json({ ok: false, error: 'insert_failed' }); }

    // Email de confirmation (ne bloque pas la réponse si l'email échoue).
    sendDeclarationEmail(cli, data);
    // Enregistre le n° transporteur chez Track123 pour le suivi automatique.
    if (data.tracking_externe) track123Import(data.tracking_externe);
    // Récompense parrainage : au 1er colis du filleul, on crédite son parrain de 5 €.
    if (cli.parrain_id) {
      (async function () {
        try {
          const { count } = await db.from('colis').select('id', { count: 'exact', head: true }).eq('client_id', cli.id);
          if (count === 1) {
            const { data: p } = await db.from('clients').select('wallet_balance').eq('id', cli.parrain_id).maybeSingle();
            if (p) {
              await db.from('clients').update({ wallet_balance: Number(p.wallet_balance || 0) + 5 }).eq('id', cli.parrain_id);
              await db.from('recharges').insert({ client_id: cli.parrain_id, montant: 5, moyen: 'parrainage', statut: 'valide' });
            }
          }
        } catch (e) { console.error('referral reward error:', e.message); }
      })();
    }

    res.json({ ok: true, colis: data });
  } catch (err) {
    console.error('declare error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ── 8) Route : lister les colis d'un client ──────────────────────────────── */
app.get('/colis', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const phone = req.clientPhone;
    const { data: cli } = await db.from('clients').select('id').eq('phone', phone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'client_not_found' });
    const { data } = await db.from('colis').select('*')
      .eq('client_id', cli.id).order('created_at', { ascending: false });
    res.json({ ok: true, colis: data || [] });
  } catch (err) {
    console.error('list colis error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ── 9) Suivi Track123 ─────────────────────────────────────────────────────
   • track123Import : enregistre un n° de suivi pour que Track123 le surveille.
   • track123Query  : récupère le statut + l'historique d'un n° de suivi.
   • extractTrack   : normalise la réponse (statut + événements) de façon
                      défensive, quelle que soit la profondeur exacte du JSON.
   ───────────────────────────────────────────────────────────────────────── */
const TRACK123_BASE = 'https://api.track123.com/gateway/open-api/tk/v2';

async function track123Import(trackNo) {
  if (!TRACK123_API_KEY || !trackNo) return;
  try {
    await fetch(TRACK123_BASE + '/track/import', {
      method: 'POST',
      headers: { 'Track123-Api-Secret': TRACK123_API_KEY, 'accept': 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify([{ trackNo: trackNo, courierCode: '' }]),
    });
  } catch (e) { console.error('track123 import error:', e.message); }
}

async function track123Query(trackNo) {
  if (!TRACK123_API_KEY || !trackNo) return null;
  try {
    const r = await fetch(TRACK123_BASE + '/track/query', {
      method: 'POST',
      headers: { 'Track123-Api-Secret': TRACK123_API_KEY, 'accept': 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({ trackNos: [trackNo] }),
    });
    return await r.json();
  } catch (e) { console.error('track123 query error:', e.message); return null; }
}

// Recherche récursive : trouve le 1er objet contenant un n° de suivi.
function findTrackObject(node, trackNo) {
  if (!node || typeof node !== 'object') return null;
  if (Array.isArray(node)) {
    for (const it of node) { const f = findTrackObject(it, trackNo); if (f) return f; }
    return null;
  }
  if (node.trackNo === trackNo || node.trackingNo === trackNo) return node;
  for (const k in node) { const f = findTrackObject(node[k], trackNo); if (f) return f; }
  return null;
}

// Traduit les statuts Track123 en libellés FR + une classe de couleur.
const TRACK123_STATUS_FR = {
  INIT:            { label: 'Enregistré',        cls: 'transit' },
  PENDING:         { label: 'En attente',        cls: 'transit' },
  INFO_RECEIVED:   { label: 'Pris en charge',    cls: 'received' },
  IN_TRANSIT:      { label: 'En transit',        cls: 'transit' },
  OUT_FOR_DELIVERY:{ label: 'En cours de livraison', cls: 'shipped' },
  DELIVERED:       { label: 'Reçu chez Tiinda 🇫🇷', cls: 'received' },
  EXCEPTION:       { label: 'Incident',          cls: 'transit' },
  FAILED_ATTEMPT:  { label: 'Tentative échouée', cls: 'transit' },
  EXPIRED:         { label: 'Expiré',            cls: 'transit' },
};

// Normalise statut + transporteur + événements depuis la réponse Track123.
function extractTrack(raw, trackNo) {
  const obj = findTrackObject(raw, trackNo) || {};
  const info = obj.trackInfo || obj.tracking || obj;
  // Statut (transitStatus est le champ principal de Track123)
  const latest = info.latestStatus || info.lastStatus || {};
  let code = (obj.transitStatus || latest.status || info.status || '').toString().toUpperCase();
  const fr = TRACK123_STATUS_FR[code] || { label: code || 'En attente', cls: 'transit' };
  // Transporteur détecté
  const li = obj.localLogisticsInfo || info.localLogisticsInfo || {};
  const courier = li.courierNameEN || li.courierNameCN || li.courierCode || '';
  const courierLink = li.courierTrackingLink || '';
  // Événements (présents une fois que Track123 a récupéré les données)
  let events = info.trackingDetails || info.events || info.trackDetails ||
               info.checkpoints || li.trackingDetails || obj.trackingDetails || [];
  if (!Array.isArray(events)) events = [];
  const norm = events.map(function (e) {
    return {
      time: e.eventTime || e.checkpointTime || e.time || e.date || '',
      detail: e.eventDetail || e.statusDescription || e.detail || e.description || e.context || '',
      location: e.address || e.location || e.eventLocation || e.city || '',
    };
  });
  return { code: code, status: fr.label, cls: fr.cls, courier: courier, courierLink: courierLink, events: norm };
}

/* ── Route : suivi d'un colis (par n° interne TND ou n° transporteur) ─────── */
app.get('/track', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const q = String(req.query.q || '').trim().replace(/[^A-Za-z0-9\-]/g, '');
    if (!q) return res.json({ ok: false, error: 'missing_query' });
    // Le colis doit appartenir au client connecté (sécurité).
    const { data: cli } = await db.from('clients').select('id').eq('phone', req.clientPhone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'client_not_found' });
    let { data: colis } = await db.from('colis').select('*')
      .eq('client_id', cli.id)
      .or('tracking_interne.eq.' + q + ',tracking_externe.eq.' + q).limit(1).maybeSingle();
    if (!colis) return res.json({ ok: false, error: 'not_found' });
    const carrierNo = colis.tracking_externe;
    if (!carrierNo) return res.json({ ok: true, colis: colis, track: null, error: 'no_carrier_number' });
    // S'assure que Track123 surveille bien ce numéro (idempotent), puis interroge.
    await track123Import(carrierNo);
    const raw = await track123Query(carrierNo);
    const track = raw ? extractTrack(raw, carrierNo) : null;
    res.json({ ok: true, colis: {
      tracking_interne: colis.tracking_interne,
      tracking_externe: colis.tracking_externe,
      description: colis.description,
      statut: colis.statut,
    }, track: track, raw: raw });
  } catch (err) {
    console.error('track error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ── Route : vérifie si un compte existe déjà (par téléphone ou email) ──────
   Utilisé à l'inscription pour bloquer les doublons et orienter vers la
   connexion. Rate-limité pour limiter l'énumération de comptes. */
app.get('/exists', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false });
    if (!rateLimit('exists:' + clientIp(req), 30, 600000)) return res.status(429).json({ ok: false, error: 'too_many_requests' });
    const phone = toE164(req.query.phone || '');
    const email = String(req.query.email || '').trim().toLowerCase();
    let phoneExists = false, emailExists = false;
    if (phone && phone.length > 5) {
      const { data } = await db.from('clients').select('id').eq('phone', phone).limit(1);
      phoneExists = !!(data && data.length);
    }
    if (email) {
      const { data } = await db.from('clients').select('id').ilike('email', email).limit(1);
      emailExists = !!(data && data.length);
    }
    res.json({ ok: true, phoneExists: phoneExists, emailExists: emailExists });
  } catch (e) {
    console.error('exists error:', e.message);
    res.json({ ok: false });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true, db: !!db, track123: !!TRACK123_API_KEY }));

/* ── 10) PANNEAU ADMIN (équipe Tiinda) ─────────────────────────────────────
   Protégé par ADMIN_TOKEN — transmis UNIQUEMENT via le header x-admin-token
   (plus jamais dans l'URL, pour ne pas fuiter dans les logs/historique). */
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!ADMIN_TOKEN || !token) return res.status(401).json({ ok: false, error: 'unauthorized' });
  const a = Buffer.from(String(token));
  const b = Buffer.from(String(ADMIN_TOKEN));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ ok: false, error: 'unauthorized' });
  next();
}

// Accès "scan entrepôt" : accepte le token ADMIN **ou** un SCAN_TOKEN dédié,
// pour pouvoir déléguer le scan à l'équipe sans donner l'accès admin complet.
function requireScan(req, res, next) {
  const token = req.headers['x-scan-token'] || req.headers['x-admin-token'];
  const ok = function (ref) { if (!ref || !token) return false; const a = Buffer.from(String(token)), b = Buffer.from(String(ref)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
  if (ok(process.env.SCAN_TOKEN) || ok(ADMIN_TOKEN)) return next();
  return res.status(401).json({ ok: false, error: 'unauthorized' });
}

// Liste tous les colis (avec infos client) — filtrable par statut.
app.get('/admin/colis', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    let q = db.from('colis').select('*, clients(prenom,nom,phone,email,tiinda_id)').order('created_at', { ascending: false });
    if (req.query.statut) q = q.eq('statut', req.query.statut);
    const { data, error } = await q;
    if (error) { console.error('admin list error:', error.message); return res.json({ ok: false, error: 'list_failed' }); }
    res.json({ ok: true, colis: data || [] });
  } catch (err) {
    console.error('admin colis error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Notifie le client d'un changement de statut (WhatsApp gratuit + SMS payant + email).
const STATUT_MSG = {
  recu: 'est bien arrivé à notre entrepôt en France',
  expedie: 'a été expédié vers le Congo',
  arrive: 'est arrivé au Congo',
  disponible: 'est disponible au retrait',
  livre: 'a été retiré. Merci !',
};
async function notifyColisStatus(clientId, colis) {
  if (!db || !clientId || !colis) return;
  const { data: cli } = await db.from('clients').select('id, prenom, email, phone, wallet_balance, notif_email, notif_sms, notif_whatsapp').eq('id', clientId).maybeSingle();
  if (!cli) return;
  const action = STATUT_MSG[colis.statut] || ('a changé de statut : ' + colis.statut);
  const ref = colis.tracking_interne || '';
  const text = 'Tiinda : votre colis ' + ref + ' ' + action + '.';
  // WhatsApp via template approuvé « tiinda_colis_update » (3 variables :
  // prénom, n° colis, statut). Envoi proactif autorisé par Meta.
  const WA_TEMPLATE_SID = process.env.TWILIO_WA_TEMPLATE_SID || 'HX2ba4d551cab40767d458174204aff69e';
  if (cli.notif_whatsapp && process.env.TWILIO_WHATSAPP_FROM) {
    try {
      await client.messages.create({
        from: 'whatsapp:' + process.env.TWILIO_WHATSAPP_FROM,
        to: 'whatsapp:' + cli.phone,
        contentSid: WA_TEMPLATE_SID,
        contentVariables: JSON.stringify({ '1': cli.prenom || 'cher client', '2': ref, '3': action }),
      });
    } catch (e) { console.error('notif wa error:', e.message); }
  }
  // SMS (payant : 0,10 € débité du wallet si solde suffisant)
  if (cli.notif_sms && process.env.TWILIO_SMS_FROM) {
    const cost = 0.10;
    if (Number(cli.wallet_balance || 0) >= cost) {
      try {
        await client.messages.create({ from: process.env.TWILIO_SMS_FROM, to: cli.phone, body: text });
        await db.from('clients').update({ wallet_balance: Number(cli.wallet_balance) - cost }).eq('id', cli.id);
        await db.from('recharges').insert({ client_id: cli.id, montant: -cost, moyen: 'sms', statut: 'valide' });
      } catch (e) { console.error('notif sms error:', e.message); }
    }
  }
  // Email (gratuit)
  if (cli.notif_email && cli.email && RESEND_API_KEY) {
    const html = '<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto"><div style="background:#0057FF;color:#fff;padding:18px;border-radius:12px 12px 0 0;text-align:center"><strong style="font-size:18px">TIINDA</strong></div><div style="border:1px solid #eee;border-top:none;padding:22px;border-radius:0 0 12px 12px"><p>Bonjour ' + (cli.prenom || '') + ',</p><p>Votre colis <strong>' + ref + '</strong> ' + action + '.</p><p style="font-size:12.5px;color:#666">Suivez votre colis depuis votre espace Tiinda.</p></div></div>';
    try {
      await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: MAIL_FROM || 'Tiinda <onboarding@resend.dev>', to: cli.email, subject: 'Tiinda — Mise à jour de votre colis ' + ref, html }) });
    } catch (e) { console.error('notif mail error:', e.message); }
  }
}

// Réception & mesure : enregistre type, dimensions, poids → transmis admin + client.
app.post('/admin/measure', requireScan, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    const code = String(b.code || '').trim().toUpperCase().replace(/[^A-Z0-9\-]/g, '');
    if (!code) return res.json({ ok: false, error: 'missing' });
    const { data: colis } = await db.from('colis').select('id, statut, client_id, tracking_interne, received_at')
      .or('tracking_interne.eq.' + code + ',tracking_externe.eq.' + code).limit(1).maybeSingle();
    if (!colis) return res.json({ ok: false, error: 'colis_introuvable' });
    // Bloque la double réception/mesure.
    if (colis.statut === 'recu' || colis.received_at) return res.json({ ok: false, error: 'deja_mesure' });
    const num = function (x) { return (x === '' || x == null) ? null : Number(x); };
    const L = num(b.longueur), W = num(b.largeur), H = num(b.hauteur), kg = num(b.poids);
    // ── Calcul du prix d'expédition Congo (même formule que la calculette) ──
    // 15 €/kg · règle volumétrique 1 kg = 6,26 L · poids facturé = max(réel, vol.) arrondi sup.
    var frais = null;
    if (L && W && H && kg) {
      const volumeL = (L * W * H) / 1000;            // cm³ → litres
      const poidsVol = volumeL / 6.26;               // poids volumétrique
      const poidsFact = Math.ceil(Math.max(kg, poidsVol));
      frais = poidsFact * 15;                         // € (15 €/kg)
    }
    const patch = {
      type_colis: b.type_colis || null,
      longueur: L, largeur: W, hauteur: H, poids: kg,
      statut: 'recu', received_at: new Date().toISOString(),
    };
    if (frais != null) patch.frais_envoi = frais;
    if (b.description) patch.description = b.description;
    const { data, error } = await db.from('colis').update(patch).eq('id', colis.id).select().single();
    if (error) { console.error('measure error:', error.message); return res.json({ ok: false, error: 'update_failed' }); }
    // Notifie le client (colis reçu + mesuré + prix d'expédition).
    if (colis.statut !== 'recu') notifyColisStatus(colis.client_id, data).catch(function(){});
    res.json({ ok: true, colis: data, frais_envoi: frais });
  } catch (err) {
    console.error('measure error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Scan entrepôt : trouve un colis par son numéro Tiinda (TND…) et met à jour
// son statut en un seul appel. Notifie le client + stocke signature/photo.
app.post('/admin/scan', requireScan, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    const code = String(b.code || '').trim().toUpperCase().replace(/[^A-Z0-9\-]/g, '');
    const statut = String(b.statut || '').trim();
    if (!code || !statut) return res.json({ ok: false, error: 'missing' });
    const { data: colis } = await db.from('colis').select('id, statut, client_id, tracking_interne, description')
      .or('tracking_interne.eq.' + code + ',tracking_externe.eq.' + code).limit(1).maybeSingle();
    if (!colis) return res.json({ ok: false, error: 'colis_introuvable' });
    // Bloque le double scan : si déjà à ce statut, on prévient.
    if (colis.statut === statut) return res.json({ ok: false, error: 'deja_scanne', statut: statut });
    const patch = { statut: statut };
    if (statut === 'recu') patch.received_at = new Date().toISOString();
    if (b.signature_url) patch.signature_url = b.signature_url;
    if (b.photo_url) patch.photo_url = b.photo_url;
    const { data, error } = await db.from('colis').update(patch).eq('id', colis.id).select().single();
    if (error) { console.error('scan update error:', error.message); return res.json({ ok: false, error: 'update_failed' }); }
    if (colis.statut !== statut) notifyColisStatus(colis.client_id, data).catch(function(){});
    // Émission auto de facture quand le colis part vers le Congo (frais d'envoi connus).
    if (statut === 'expedie' && data.frais_envoi && colis.statut !== 'expedie') {
      emitInvoice(colis.client_id, 'Expédition ' + data.tracking_interne + ' vers le Congo', data.frais_envoi, data.tracking_interne).catch(function(){});
    }
    res.json({ ok: true, colis: data });
  } catch (err) {
    console.error('scan error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Met à jour un colis : statut, poids, dimensions, photo, frais d'envoi.
app.post('/admin/colis/update', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    if (!b.id) return res.json({ ok: false, error: 'missing_id' });
    const patch = {};
    if (b.statut) patch.statut = b.statut;
    if (b.poids != null && b.poids !== '') patch.poids = b.poids;
    if (b.longueur != null && b.longueur !== '') patch.longueur = b.longueur;
    if (b.largeur != null && b.largeur !== '') patch.largeur = b.largeur;
    if (b.hauteur != null && b.hauteur !== '') patch.hauteur = b.hauteur;
    if (b.photo_url) patch.photo_url = b.photo_url;
    if (b.signature_url) patch.signature_url = b.signature_url;
    if (b.frais_envoi != null && b.frais_envoi !== '') patch.frais_envoi = b.frais_envoi;
    if (b.statut === 'recu') patch.received_at = new Date().toISOString();
    // Statut avant mise à jour (pour notifier seulement si changement réel).
    const { data: before } = await db.from('colis').select('statut, client_id, tracking_interne, description').eq('id', b.id).maybeSingle();
    const { data, error } = await db.from('colis').update(patch).eq('id', b.id).select().single();
    if (error) { console.error('admin update error:', error.message); return res.json({ ok: false, error: 'update_failed' }); }
    // Notifie le client si le STATUT a changé.
    if (b.statut && before && before.statut !== b.statut) {
      notifyColisStatus(before.client_id, data).catch(function(){});
    }
    res.json({ ok: true, colis: data });
  } catch (err) {
    console.error('admin update error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Indicateurs (KPI) pour le pilotage : abonnés, colis, CA, répartitions.
app.get('/admin/stats', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: clients } = await db.from('clients').select('offre, ville, created_at, wallet_balance, last_seen');
    const { data: colis } = await db.from('colis').select('statut, valeur, poids, frais_envoi, created_at');
    const cl = clients || [], co = colis || [];
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const onlineCut = new Date(now.getTime() - 5 * 60000); // en ligne = vu il y a < 5 min
    const norm = function (s) { s = (s || '').toLowerCase(); return s.indexOf('mokili') >= 0 ? 'mokili' : s.indexOf('familia') >= 0 ? 'familia' : 'bokolo'; };
    const byOffre = { bokolo: 0, familia: 0, mokili: 0 };
    const byOffreToday = { bokolo: 0, familia: 0, mokili: 0 };
    const byVille = {};
    let clientsThisMonth = 0, clientsToday = 0, onlineNow = 0;
    cl.forEach(function (c) {
      var o = norm(c.offre); byOffre[o]++;
      const v = (c.ville || 'Inconnue'); byVille[v] = (byVille[v] || 0) + 1;
      if (c.created_at && new Date(c.created_at) >= monthStart) clientsThisMonth++;
      if (c.created_at && new Date(c.created_at) >= dayStart) { clientsToday++; byOffreToday[o]++; }
      if (c.last_seen && new Date(c.last_seen) >= onlineCut) onlineNow++;
    });
    const byStatut = {};
    let valeurTotale = 0, poidsTotal = 0, fraisEnvoiTotal = 0, colisThisMonth = 0, colisToday = 0, fraisEnvoiToday = 0;
    co.forEach(function (c) {
      byStatut[c.statut || 'declare'] = (byStatut[c.statut || 'declare'] || 0) + 1;
      valeurTotale += Number(c.valeur || 0);
      poidsTotal += Number(c.poids || 0);
      fraisEnvoiTotal += Number(c.frais_envoi || 0);
      if (c.created_at && new Date(c.created_at) >= monthStart) colisThisMonth++;
      if (c.created_at && new Date(c.created_at) >= dayStart) { colisToday++; fraisEnvoiToday += Number(c.frais_envoi || 0); }
    });
    res.json({ ok: true, stats: {
      clientsTotal: cl.length, clientsThisMonth: clientsThisMonth, clientsToday: clientsToday, onlineNow: onlineNow,
      colisTotal: co.length, colisThisMonth: colisThisMonth, colisToday: colisToday,
      byOffre: byOffre, byOffreToday: byOffreToday, byVille: byVille, byStatut: byStatut,
      valeurTotale: valeurTotale, poidsTotal: poidsTotal, fraisEnvoiTotal: fraisEnvoiTotal, fraisEnvoiToday: fraisEnvoiToday,
    }});
  } catch (err) {
    console.error('admin stats error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Présence « en ligne » : le tableau de bord client appelle ceci périodiquement.
app.get('/presence', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false });
    const phone = req.clientPhone;
    if (phone) await db.from('clients').update({ last_seen: new Date().toISOString() }).eq('phone', phone);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false }); }
});

/* ── 11) WALLET TIINDA ─────────────────────────────────────────────────────
   Un seul solde par client (clients.wallet_balance). Deux canaux de recharge
   qui s'additionnent : carte (Shopify) et code de recharge. Chaque crédit est
   tracé dans la table `recharges`.
   ───────────────────────────────────────────────────────────────────────── */

// Crédite le wallet d'un client + journalise dans `recharges`.
async function creditWallet(clientId, montant, moyen, code) {
  if (!db) return null;
  const { data: cli } = await db.from('clients').select('wallet_balance').eq('id', clientId).maybeSingle();
  const newBal = Number((cli && cli.wallet_balance) || 0) + Number(montant);
  await db.from('clients').update({ wallet_balance: newBal }).eq('id', clientId);
  await db.from('recharges').insert({ client_id: clientId, montant: montant, moyen: moyen || 'code', code_recharge: code || null, statut: 'valide' });
  return newBal;
}

// Préférences de notification : charger.
app.get('/prefs', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data } = await db.from('clients').select('notif_email, notif_sms, notif_whatsapp, twofa').eq('phone', req.clientPhone).limit(1).maybeSingle();
    res.json({ ok: true, prefs: data || { notif_email: true, notif_sms: false, notif_whatsapp: true, twofa: false } });
  } catch (err) {
    console.error('prefs get error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Préférences de notification : enregistrer.
app.post('/prefs', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    // On ne met à jour QUE les champs présents (évite d'écraser les autres).
    const patch = {};
    if ('notif_email' in b) patch.notif_email = !!b.notif_email;
    if ('notif_sms' in b) patch.notif_sms = !!b.notif_sms;
    if ('notif_whatsapp' in b) patch.notif_whatsapp = !!b.notif_whatsapp;
    if ('twofa' in b) patch.twofa = !!b.twofa;
    if (Object.keys(patch).length) await db.from('clients').update(patch).eq('phone', req.clientPhone);
    res.json({ ok: true });
  } catch (err) {
    console.error('prefs set error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Changement de mot de passe (client connecté) : vérifie l'ancien, pose le nouveau.
app.post('/password/change', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const oldPw = String(req.body.old_password || '');
    const newPw = String(req.body.new_password || '');
    if (newPw.length < 8) return res.json({ ok: false, error: 'too_short' });
    const { data: cli } = await db.from('clients').select('id, password_hash').eq('phone', req.clientPhone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'not_found' });
    // Si un mot de passe existe déjà, on exige l'ancien correct.
    if (cli.password_hash && !verifyPassword(oldPw, cli.password_hash)) {
      return res.json({ ok: false, error: 'wrong_password' });
    }
    await db.from('clients').update({ password_hash: hashPassword(newPw) }).eq('id', cli.id);
    res.json({ ok: true });
  } catch (err) {
    console.error('password change error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Activité récente du client : événements dérivés des colis + recharges.
// ── FACTURES ───────────────────────────────────────────────────────────────
async function emitInvoice(clientId, description, montant, ref) {
  if (!db || !clientId) return null;
  const year = new Date().getFullYear();
  const { count } = await db.from('factures').select('id', { count: 'exact', head: true });
  const num = 'TND-INV-' + year + '-' + String((count || 0) + 1).padStart(4, '0');
  const { data, error } = await db.from('factures').insert({
    client_id: clientId, numero: num, description: description || 'Service Tiinda',
    montant: Number(montant || 0), ref: ref || null, statut: 'emise',
  }).select().single();
  if (error) { console.error('emit invoice error:', error.message); return null; }
  return data;
}
app.get('/factures', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: cli } = await db.from('clients').select('id').eq('phone', req.clientPhone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'not_found' });
    const { data } = await db.from('factures').select('*').eq('client_id', cli.id).eq('statut', 'emise').order('created_at', { ascending: false });
    res.json({ ok: true, factures: data || [] });
  } catch (err) { console.error('factures error:', err.message); res.status(500).json({ ok: false, error: 'server_error' }); }
});
app.get('/admin/factures', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data } = await db.from('factures').select('*, clients(prenom,nom,tiinda_id,phone)').order('created_at', { ascending: false }).limit(300);
    res.json({ ok: true, factures: data || [] });
  } catch (err) { console.error('admin factures error:', err.message); res.status(500).json({ ok: false, error: 'server_error' }); }
});
app.post('/admin/factures/create', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    const tid = String(b.tiinda_id || '').trim().toUpperCase();
    const { data: cli } = await db.from('clients').select('id').eq('tiinda_id', tid).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'client_introuvable' });
    const inv = await emitInvoice(cli.id, b.description, b.montant, b.ref);
    res.json({ ok: !!inv, facture: inv });
  } catch (err) { console.error('create facture error:', err.message); res.status(500).json({ ok: false, error: 'server_error' }); }
});
app.post('/admin/factures/update', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    if (!b.id) return res.json({ ok: false, error: 'missing_id' });
    const patch = {};
    if (b.description != null) patch.description = b.description;
    if (b.montant != null && b.montant !== '') patch.montant = Number(b.montant);
    if (b.statut) patch.statut = b.statut;
    const { data, error } = await db.from('factures').update(patch).eq('id', b.id).select().single();
    if (error) { console.error('update facture error:', error.message); return res.json({ ok: false, error: 'update_failed' }); }
    res.json({ ok: true, facture: data });
  } catch (err) { console.error('update facture error:', err.message); res.status(500).json({ ok: false, error: 'server_error' }); }
});

// Activité récente du client : événements dérivés des colis + recharges.
app.get('/activity', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: cli } = await db.from('clients').select('id').eq('phone', req.clientPhone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'not_found' });
    const { data: colis } = await db.from('colis').select('tracking_interne, description, statut, created_at, received_at').eq('client_id', cli.id).order('created_at', { ascending: false }).limit(20);
    const { data: rech } = await db.from('recharges').select('montant, moyen, created_at').eq('client_id', cli.id).order('created_at', { ascending: false }).limit(20);
    const STMSG = { declare: 'déclaré', recu: 'reçu à notre entrepôt en France', expedie: 'expédié vers le Congo', arrive: 'arrivé au Congo', disponible: 'disponible au retrait', livre: 'retiré' };
    const events = [];
    (colis || []).forEach(function (c) {
      events.push({ type: 'colis', when: c.received_at || c.created_at, title: 'Colis ' + c.tracking_interne + ' ' + (STMSG[c.statut] || c.statut), detail: (c.description || '') });
    });
    (rech || []).forEach(function (r) {
      const m = Number(r.montant || 0);
      const isReward = r.moyen === 'parrainage';
      events.push({ type: 'wallet', when: r.created_at,
        title: isReward ? 'Récompense parrainage +' + m + ' €' : (m >= 0 ? 'Recharge de ' + m + ' €' : 'Débit de ' + Math.abs(m) + ' €'),
        detail: isReward ? 'Un filleul a effectué son premier envoi.' : (r.moyen === 'code' ? 'Par code de recharge' : (r.moyen === 'carte' ? 'Par carte bancaire' : (r.moyen === 'sms' ? 'Notification SMS' : ''))) });
    });
    events.sort(function (a, b) { return new Date(b.when) - new Date(a.when); });
    res.json({ ok: true, events: events.slice(0, 25) });
  } catch (err) {
    console.error('activity error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// ── DEMANDES DE MODIFICATION DE PROFIL (validées par l'admin) ───────────────
// Le client soumet une demande ; rien n'est appliqué tant que l'admin n'a pas validé.
app.get('/profil/request', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: cli } = await db.from('clients').select('id').eq('phone', req.clientPhone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'not_found' });
    const { data } = await db.from('profile_requests').select('id').eq('client_id', cli.id).eq('statut', 'en_attente').limit(1);
    res.json({ ok: true, pending: !!(data && data.length) });
  } catch (err) { console.error('profil get error:', err.message); res.status(500).json({ ok: false, error: 'server_error' }); }
});
app.post('/profil/request', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: cli } = await db.from('clients').select('id').eq('phone', req.clientPhone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'not_found' });
    // Une seule demande en attente à la fois : on remplace l'ancienne.
    await db.from('profile_requests').delete().eq('client_id', cli.id).eq('statut', 'en_attente');
    const b = req.body || {};
    const payload = { prenom: b.prenom, nom: b.nom, naissance: b.naissance, genre: b.genre, email: b.email, ville: b.ville, commune: b.commune, rue: b.rue, repere: b.repere };
    const { error } = await db.from('profile_requests').insert({ client_id: cli.id, payload: payload, statut: 'en_attente' });
    if (error) { console.error('profil insert error:', error.message); return res.json({ ok: false, error: 'insert_failed' }); }
    res.json({ ok: true });
  } catch (err) { console.error('profil post error:', err.message); res.status(500).json({ ok: false, error: 'server_error' }); }
});
// (ADMIN) Liste des demandes en attente.
app.get('/admin/profil-requests', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data } = await db.from('profile_requests').select('*, clients(prenom,nom,tiinda_id,phone)').eq('statut', 'en_attente').order('created_at', { ascending: false });
    res.json({ ok: true, requests: data || [] });
  } catch (err) { console.error('admin profil list error:', err.message); res.status(500).json({ ok: false, error: 'server_error' }); }
});
// (ADMIN) Approuver (applique les changements) ou rejeter une demande.
app.post('/admin/profil-requests/handle', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    if (!b.id) return res.json({ ok: false, error: 'missing_id' });
    const { data: reqRow } = await db.from('profile_requests').select('*').eq('id', b.id).maybeSingle();
    if (!reqRow) return res.json({ ok: false, error: 'not_found' });
    if (b.action === 'approve') {
      const p = reqRow.payload || {};
      const patch = {};
      ['prenom','nom','email','ville'].forEach(function (k) { if (p[k]) patch[k] = p[k]; });
      // Champs adresse/identité étendus (colonnes optionnelles).
      ['naissance','genre','commune','rue','repere'].forEach(function (k) { if (p[k] != null) patch[k] = p[k]; });
      if (patch.email) patch.email = String(patch.email).toLowerCase();
      await db.from('clients').update(patch).eq('id', reqRow.client_id);
      await db.from('profile_requests').update({ statut: 'approuvee' }).eq('id', b.id);
    } else {
      await db.from('profile_requests').update({ statut: 'rejetee' }).eq('id', b.id);
    }
    res.json({ ok: true });
  } catch (err) { console.error('admin profil handle error:', err.message); res.status(500).json({ ok: false, error: 'server_error' }); }
});

// Programme de parrainage : code, lien, filleuls, récompenses gagnées.
app.get('/referral', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: me } = await db.from('clients').select('id, tiinda_id').eq('phone', req.clientPhone).limit(1).maybeSingle();
    if (!me) return res.json({ ok: false, error: 'not_found' });
    const base = (process.env.SITE_URL || 'https://tiinda.com');
    const { data: filleuls } = await db.from('clients').select('prenom, nom, created_at, id').eq('parrain_id', me.id).order('created_at', { ascending: false });
    // Récompenses parrainage déjà créditées (tracées dans recharges, moyen='parrainage').
    const { data: recs } = await db.from('recharges').select('montant').eq('client_id', me.id).eq('moyen', 'parrainage');
    let gains = 0; (recs || []).forEach(function (r) { gains += Number(r.montant || 0); });
    res.json({
      ok: true,
      code: me.tiinda_id,
      link: base + '/?ref=' + me.tiinda_id,
      count: (filleuls || []).length,
      gains: gains,
      filleuls: (filleuls || []).map(function (f) { return { nom: ((f.prenom || '') + ' ' + (f.nom || '')).trim(), date: f.created_at }; }),
    });
  } catch (err) {
    console.error('referral error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Solde + historique de recharges d'un client.
app.get('/wallet', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const phone = req.clientPhone;
    const { data: cli } = await db.from('clients').select('id, wallet_balance').eq('phone', phone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'client_not_found' });
    const { data: hist } = await db.from('recharges').select('*').eq('client_id', cli.id).order('created_at', { ascending: false }).limit(50);
    res.json({ ok: true, balance: Number(cli.wallet_balance || 0), history: hist || [] });
  } catch (err) {
    console.error('wallet error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Utiliser un code de recharge → crédite le wallet.
app.post('/wallet/redeem', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    if (!rateLimit('redeem:' + clientIp(req), 15, 600000)) return res.status(429).json({ ok: false, error: 'too_many_requests' });
    const phone = req.clientPhone;
    const code = String(req.body.code || '').trim().toUpperCase().replace(/[^A-Z0-9\-]/g, '');
    if (!code) return res.json({ ok: false, error: 'missing_code' });
    const { data: cli } = await db.from('clients').select('id').eq('phone', phone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'client_not_found' });
    const { data: rc } = await db.from('recharge_codes').select('*').eq('code', code).limit(1).maybeSingle();
    if (!rc) return res.json({ ok: false, error: 'code_invalide' });
    if (rc.used) return res.json({ ok: false, error: 'code_deja_utilise' });
    // Marque le code utilisé puis crédite.
    await db.from('recharge_codes').update({ used: true, used_by: cli.id, used_at: new Date().toISOString() }).eq('id', rc.id);
    const newBal = await creditWallet(cli.id, rc.montant, 'code', code);
    res.json({ ok: true, montant: Number(rc.montant), balance: newBal });
  } catch (err) {
    console.error('redeem error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// (ADMIN) Crédit par CARTE / manuel : ajoute du crédit au wallet d'un client.
app.post('/admin/wallet/credit', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    if (!b.client_id || !b.montant) return res.json({ ok: false, error: 'missing' });
    const newBal = await creditWallet(b.client_id, b.montant, b.moyen || 'carte', null);
    res.json({ ok: true, balance: newBal });
  } catch (err) {
    console.error('admin credit error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// (ADMIN) Générer des codes de recharge (montant + quantité).
app.post('/admin/codes/generate', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const montant = Number(req.body.montant || 0);
    const count = Math.min(Math.max(parseInt(req.body.count || 1, 10), 1), 100);
    if (!montant) return res.json({ ok: false, error: 'missing_montant' });
    const rnd = function () { var s = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', o = ''; for (var i = 0; i < 4; i++) o += s[Math.floor(Math.random() * s.length)]; return o; };
    const rows = [];
    for (var i = 0; i < count; i++) rows.push({ code: 'TND-' + rnd() + '-' + rnd(), montant: montant });
    const { data, error } = await db.from('recharge_codes').insert(rows).select();
    if (error) { console.error('codes gen error:', error.message); return res.json({ ok: false, error: 'gen_failed' }); }
    res.json({ ok: true, codes: data || [] });
  } catch (err) {
    console.error('codes error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// (ADMIN) Liste des codes de recharge.
app.get('/admin/codes', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data } = await db.from('recharge_codes').select('*').order('created_at', { ascending: false }).limit(200);
    res.json({ ok: true, codes: data || [] });
  } catch (err) {
    console.error('list codes error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// (ADMIN) Liste complète des clients : solde, formule, présence, CA, dernier achat.
app.get('/admin/clients', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data } = await db.from('clients').select('id, tiinda_id, prenom, nom, phone, email, ville, offre, wallet_balance, last_seen, created_at').order('created_at', { ascending: false });
    const { data: rech } = await db.from('recharges').select('client_id, montant, created_at');
    const { data: cols } = await db.from('colis').select('client_id, frais_envoi, created_at');
    // Agrège CA total (recharges + frais d'envoi) et la date du dernier mouvement par client.
    const ca = {}, last = {};
    (rech || []).forEach(function (r) {
      ca[r.client_id] = (ca[r.client_id] || 0) + Number(r.montant || 0);
      if (r.created_at && (!last[r.client_id] || new Date(r.created_at) > new Date(last[r.client_id]))) last[r.client_id] = r.created_at;
    });
    (cols || []).forEach(function (c) {
      ca[c.client_id] = (ca[c.client_id] || 0) + Number(c.frais_envoi || 0);
      if (c.created_at && (!last[c.client_id] || new Date(c.created_at) > new Date(last[c.client_id]))) last[c.client_id] = c.created_at;
    });
    const cut = Date.now() - 5 * 60000;
    const actifCut = Date.now() - 60 * 86400000; // actif = activité < 60 jours
    const rows = (data || []).map(function (c) {
      const online = c.last_seen ? (new Date(c.last_seen).getTime() >= cut) : false;
      const lastAct = last[c.id] || c.created_at;
      const actif = online || (lastAct && new Date(lastAct).getTime() >= actifCut);
      return {
        tiinda_id: c.tiinda_id, prenom: c.prenom, nom: c.nom, phone: c.phone, email: c.email,
        ville: c.ville, offre: c.offre, wallet_balance: Number(c.wallet_balance || 0),
        online: online, ca_total: Number(ca[c.id] || 0), dernier_achat: last[c.id] || null,
        actif: !!actif, created_at: c.created_at,
      };
    });
    res.json({ ok: true, clients: rows });
  } catch (err) {
    console.error('admin clients error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.listen(PORT, () => {
  console.log(`TIINDA backend en écoute sur le port ${PORT} — Supabase: ${db ? 'OK' : 'NON configuré'}`);
});
