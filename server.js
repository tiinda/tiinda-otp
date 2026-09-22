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

/* ── Webhook Shopify « commande payée » — crédit automatique du wallet ──────
   Doit lire le corps BRUT (avant express.json) pour vérifier la signature HMAC.
   Bonus : +5% sur 20 €, +10% sur 50 €. ───────────────────────────────────── */
const CREDIT_BONUS = { 10: 0, 20: 0.05, 50: 0.10 };
app.post('/webhook/order-paid', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET || SHOPIFY_API_SECRET || '';
    const hmac = req.headers['x-shopify-hmac-sha256'] || '';
    const digest = crypto.createHmac('sha256', secret).update(req.body).digest('base64');
    let okSig = false;
    try { okSig = crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(String(hmac))); } catch (e) { okSig = false; }
    if (!okSig) return res.status(401).send('bad hmac');
    res.status(200).send('ok'); // on répond vite à Shopify
    if (!db) return;
    const order = JSON.parse(req.body.toString('utf8'));
    // 🔒 Sécurité : on ignore les commandes de TEST (carte 4242…) → pas de crédit fictif.
    if (order.test === true) { console.log('webhook: commande TEST ignorée'); return; }

    /* ── Coolibo : le numéro de suivi n'existe qu'ici ────────────────────────
       La page /envoi ne crée plus rien : elle range le descriptif du colis
       dans la propriété _coolibo de la ligne de commande. Le numéro CLB est
       généré au paiement encaissé, une seule fois par commande (clé
       shopify_order + index unique côté base). */
    await coolliboDepuisCommande(order);

    const email = (order.email || (order.customer && order.customer.email) || '').trim().toLowerCase();
    if (!email) return;
    const { data: cli } = await db.from('clients').select('id, prenom, email, wallet_balance').ilike('email', email).limit(1).maybeSingle();
    if (!cli) { console.error('webhook: client introuvable', email); return; }
    let creditTotal = 0;
    (order.line_items || []).forEach(function (it) {
      const m = /credit[- ]?tiinda[- ]?(\d+)/i.exec((it.sku || '') + ' ' + (it.title || '') + ' ' + (it.handle || ''));
      let base = 0;
      if (m) base = Number(m[1]);
      else { const p = Math.round(Number(it.price || 0)); if (CREDIT_BONUS[p] != null) base = p; }
      if (base) creditTotal += base * (it.quantity || 1) * (1 + (CREDIT_BONUS[base] || 0));
    });
    if (creditTotal <= 0) return; // pas un achat de crédit
    creditTotal = Math.round(creditTotal * 100) / 100;
    const newBal = Number(cli.wallet_balance || 0) + creditTotal;
    await db.from('clients').update({ wallet_balance: newBal }).eq('id', cli.id);
    await db.from('recharges').insert({ client_id: cli.id, montant: creditTotal, moyen: 'carte', code_recharge: 'CMD-' + (order.order_number || order.id || ''), statut: 'valide' });
    console.log('webhook: +' + creditTotal + ' € → ' + email + ' (solde ' + newBal + ')');
  } catch (err) {
    console.error('webhook order-paid error:', err.message);
  }
});

/* Génère « CLB-2026-7KPYIW » — année + 6 caractères base36. */
function genTrackingCoolibo() {
  const y = new Date().getFullYear();
  let r = '';
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const b = crypto.randomBytes(6);
  for (let i = 0; i < 6; i++) r += A[b[i] % A.length];
  return 'CLB-' + y + '-' + r;
}

async function coolliboDepuisCommande(order) {
  try {
    if (!db) return;
    const ref = 'SHOP-' + (order.id || order.order_number || '');
    if (ref === 'SHOP-') return;

    /* Idempotence : un webhook rejoué ne recrée rien. */
    const { data: deja } = await db.from('envois_coolibo')
      .select('id').eq('shopify_order', ref).limit(1).maybeSingle();
    if (deja) { console.log('coolibo: commande déjà traitée', ref); return; }

    const email = (order.email || (order.customer && order.customer.email) || '').trim().toLowerCase();
    const lignes = [];

    (order.line_items || []).forEach(function (it) {
      const props = it.properties || [];
      const brut = (props.find ? props.find((p) => p && p.name === '_coolibo') : null);
      if (!brut || !brut.value) return;
      let d;
      try { d = JSON.parse(brut.value); } catch (e) { return; }

      const n = Math.max(1, parseInt(d.qty, 10) || 1);
      for (let i = 0; i < n; i++) {
        lignes.push({
          tracking_interne: genTrackingCoolibo(),
          statut: 'paye',
          shopify_order: ref,
          mode: d.mode || null,
          relais: d.relais || null,
          relais_id: d.relaisId || null,
          carton: d.carton || null,
          longueur: d.l != null ? Number(d.l) : null,
          largeur: d.w != null ? Number(d.w) : null,
          hauteur: d.h != null ? Number(d.h) : null,
          poids: d.kg != null ? Number(d.kg) : null,
          valeur: d.declared != null ? Number(d.declared) : null,
          zip: d.zip || null,
          ville: d.city || null,
          dest_nom: d.destNom || null,
          dest_phone: d.destTel || null,
          dest_ville: d.destVille || null,
          dest_quartier: d.destQuartier || null,
          dest_mode: d.destMode || null,
          email: email || null,
          nb_colis: n,
          frais_envoi: d.total != null ? Number(d.total) : null,
          type_colis: d.type || 'carton',
        });
      }
    });

    if (!lignes.length) return;   // commande sans envoi Coolibo

    const { error } = await db.from('envois_coolibo').insert(lignes);
    if (error) {
      /* 23505 = doublon sur shopify_order : deux webhooks en parallèle. */
      if (String(error.code) === '23505') { console.log('coolibo: doublon évité', ref); return; }
      console.error('coolibo insert:', error.message);
      return;
    }
    console.log('coolibo: ' + lignes.length + ' envoi(s) créé(s) pour ' + ref +
      ' → ' + lignes.map((l) => l.tracking_interne).join(', '));
    envoyerEtiquetteCoolibo(email, lignes).catch(function () {});
  } catch (e) {
    console.error('coolibo webhook error:', e.message);
  }
}

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

/* Recherche d'un client par téléphone, très tolérante au format :
   espaces, et « 0 » présent ou non après l'indicatif
   (+242069009078 ↔ +24269009078, +330628018900 ↔ +33628018900).
   Repli par suffixe (8 derniers chiffres) si aucune variante exacte. */
async function findClientByPhone(select, phone) {
  if (!db || !phone) return null;
  const raw = String(phone).replace(/\s/g, '');
  const cands = new Set([raw]);
  // Indicatifs connus de Tiinda (du plus long au plus court pour la priorité).
  const codes = ['243', '242', '33', '32', '1'];
  const digits = raw.replace(/[^\d]/g, '');
  codes.forEach(function (cc) {
    if (digits.indexOf(cc) === 0) {
      const rest = digits.slice(cc.length);
      const noZero = rest.replace(/^0+/, '');
      cands.add('+' + cc + rest);
      cands.add('+' + cc + noZero);       // sans 0 après l'indicatif
      cands.add('+' + cc + '0' + noZero); // avec 0 après l'indicatif
    }
  });
  const list = Array.from(cands);
  let { data } = await db.from('clients').select(select).in('phone', list).limit(1);
  if (data && data[0]) return data[0];
  // Repli : compare les 8 derniers chiffres (ignore indicatif + 0).
  const suffix = digits.slice(-8);
  if (suffix.length === 8) {
    const r = await db.from('clients').select(select + ', phone').ilike('phone', '%' + suffix);
    if (r.data && r.data.length) {
      const exact = r.data.find(function (c) { return String(c.phone || '').replace(/[^\d]/g, '').slice(-8) === suffix; });
      if (exact) return exact;
    }
  }
  return null;
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

/* ── 3 bis) LIMITATION DES ENVOIS DE CODE ─────────────────────────────────
   Chaque code envoyé est facturé. On refuse donc l'envoi si :
     1. le numéro a déjà été vérifié une fois
     2. le numéro appartient déjà à un client
     3. le dernier code date de moins d'une minute
     4. trois codes ont déjà été envoyés à ce numéro
     5. l'indicatif n'est pas desservi par Tiinda
     6. le plafond global du jour est atteint

   Table à créer dans Supabase (SQL Editor) :

     create table if not exists otp_log (
       phone    text primary key,
       envois   integer     not null default 0,
       dernier  timestamptz not null default now(),
       verifie  boolean     not null default false,
       cree_le  timestamptz not null default now()
     );
     create index if not exists otp_log_dernier_idx on otp_log (dernier);
   ───────────────────────────────────────────────────────────────────────── */
const OTP_DELAI_MS   = 60 * 1000;   // 60 secondes entre deux codes
const OTP_MAX_NUMERO = 3;           // 3 codes maximum par numéro
const OTP_MAX_JOUR   = 100;         // plafond global de sécurité sur 24 h
const OTP_INDICATIFS = ['+243', '+242', '+33', '+32', '+41', '+49', '+39', '+34', '+44'];

function otpIndicatifOk(phone) {
  if (!/^\+[1-9]\d{7,14}$/.test(phone || '')) return false;
  return OTP_INDICATIFS.some((i) => String(phone).startsWith(i));
}

async function otpVolumeDuJour() {
  if (!db) return 0;
  const depuis = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { count } = await db
    .from('otp_log')
    .select('phone', { count: 'exact', head: true })
    .gte('dernier', depuis);
  return count || 0;
}

/* Décide si un code peut partir. Renvoie { ok, raison, message, reste }. */
async function otpAutorise(phone) {
  if (!otpIndicatifOk(phone)) {
    return { ok: false, raison: 'indicatif', message: "Ce numéro n'est pas desservi par Tiinda." };
  }
  if (!db) return { ok: true };   // sans base, on ne bloque pas le service

  // Déjà client ? Inutile de payer un code, il doit se connecter.
  const dejaClient = await findClientByPhone('id', phone);
  if (dejaClient) {
    return { ok: false, raison: 'client', message: 'Ce numéro est déjà associé à un compte Tiinda. Connectez-vous avec votre email et votre mot de passe.' };
  }

  const { data } = await db.from('otp_log').select('*').eq('phone', phone).maybeSingle();
  if (data) {
    if (data.verifie) {
      return { ok: false, raison: 'verifie', message: 'Ce numéro a déjà été vérifié. Connectez-vous avec votre email et votre mot de passe.' };
    }
    if ((data.envois || 0) >= OTP_MAX_NUMERO) {
      return { ok: false, raison: 'quota', message: 'Trop de codes demandés pour ce numéro. Écrivez-nous sur WhatsApp.' };
    }
    const reste = OTP_DELAI_MS - (Date.now() - new Date(data.dernier).getTime());
    if (reste > 0) {
      const s = Math.ceil(reste / 1000);
      return { ok: false, raison: 'delai', reste: s, message: 'Patientez ' + s + ' secondes avant de redemander un code.' };
    }
  }

  if (await otpVolumeDuJour() >= OTP_MAX_JOUR) {
    return { ok: false, raison: 'plafond', message: 'Service momentanément indisponible. Réessayez plus tard.' };
  }
  return { ok: true };
}

/* À appeler après un envoi Twilio réussi (on ne compte que les vrais envois). */
async function otpEnregistre(phone) {
  if (!db) return;
  try {
    const { data } = await db.from('otp_log').select('envois').eq('phone', phone).maybeSingle();
    await db.from('otp_log').upsert({
      phone,
      envois: ((data && data.envois) || 0) + 1,
      dernier: new Date().toISOString(),
    });
  } catch (e) { console.error('otp_log envoi:', e.message); }
}

/* À appeler dès que Twilio confirme le code : ce numéro ne coûtera plus rien. */
async function otpMarqueVerifie(phone) {
  if (!db) return;
  try {
    await db.from('otp_log').upsert({
      phone,
      verifie: true,
      dernier: new Date().toISOString(),
    });
  } catch (e) { console.error('otp_log verifie:', e.message); }
}

/* ── 4) Route : envoi du code (WhatsApp ou SMS selon OTP_CHANNEL) ────────── */
app.post('/send', verifyShopifyProxy, async (req, res) => {
  try {
    if (!rateLimit('send:' + clientIp(req), 8, 600000)) return res.status(429).json({ ok: false, error: 'too_many_requests' });
    const phone = toE164(req.body.phone);
    if (!phone || phone.length < 8) return res.status(400).json({ ok: false, error: 'invalid phone' });

    // Garde-fou : aucun code payant n'est envoyé si une règle est enfreinte.
    const garde = await otpAutorise(phone);
    if (!garde.ok) {
      console.log('otp refuse', phone, garde.raison);
      return res.json({ ok: false, error: garde.raison, message: garde.message, reste: garde.reste });
    }

    await client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({ to: phone, channel: process.env.OTP_CHANNEL || 'whatsapp' });
    await otpEnregistre(phone);
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

    // Numéro vérifié : plus jamais d'envoi payant sur ce numéro.
    await otpMarqueVerifie(phone);

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
      created_at: data.created_at, abonnement_fin: data.abonnement_fin,
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

// Changement de forfait payé avec le solde Tiinda (1 mois débité immédiatement).
app.post('/forfait/change-wallet', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const PRIX = { bokolo: 9.99, familia: 19.90, mokili: 49.90 };
    const NOM  = { bokolo: 'BOKOLO', familia: 'FAMILIA', mokili: 'MOKILI PRO' };
    const RANG = { 'BOKOLO': 1, 'FAMILIA': 2, 'MOKILI PRO': 3 };
    const PRIX_PAR_NOM = { 'BOKOLO': 9.99, 'FAMILIA': 19.90, 'MOKILI PRO': 49.90 };

    const key = String(req.body.key || '').toLowerCase();
    if (!PRIX[key]) return res.json({ ok: false, error: 'forfait_invalide' });

    const { data: cli } = await db.from('clients')
      .select('id, wallet_balance, offre, abonnement_fin')
      .eq('phone', req.clientPhone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'client_not_found' });

    const solde = Number(cli.wallet_balance || 0);
    const cible = NOM[key];
    const actuelle = String(cli.offre || '').toUpperCase();
    const fin = cli.abonnement_fin ? new Date(cli.abonnement_fin) : null;
    const maintenant = new Date();
    const actif = fin && fin > maintenant && actuelle && actuelle !== 'DECOUVERTE';

    let prix, nouvelleFin, mode, detail = null;

    if (!actif) {
      // Aucun forfait en cours : mois plein.
      prix = PRIX[key];
      nouvelleFin = new Date(maintenant); nouvelleFin.setMonth(nouvelleFin.getMonth() + 1);
      mode = 'souscription';

    } else if (actuelle === cible) {
      return res.json({
        ok: false, error: 'deja_abonne', offre: actuelle, fin: cli.abonnement_fin,
        message: 'Vous avez déjà le forfait ' + actuelle + ' jusqu\'au '
               + fin.toLocaleDateString('fr-FR') + '.'
      });

    } else if ((RANG[cible] || 0) > (RANG[actuelle] || 0)) {
      // MONTÉE EN GAMME : effet immédiat, on paie la différence au prorata.
      const joursRestants = Math.max(0, Math.ceil((fin - maintenant) / 86400000));
      const diffMensuelle = PRIX_PAR_NOM[cible] - (PRIX_PAR_NOM[actuelle] || 0);
      prix = Math.round((diffMensuelle * joursRestants / 30) * 100) / 100;
      if (prix < 0) prix = 0;
      nouvelleFin = fin;                    // l'échéance ne change pas
      mode = 'montee_prorata';
      detail = { jours_restants: joursRestants, difference_mensuelle: diffMensuelle };

    } else {
      // DESCENTE EN GAMME : pas de remboursement, effet à l'échéance.
      await db.from('clients').update({ offre_suivante: cible }).eq('id', cli.id);
      return res.json({
        ok: true, programme: true, offre_actuelle: actuelle, offre_suivante: cible,
        fin: cli.abonnement_fin, solde: solde,
        message: 'Passage à ' + cible + ' programmé pour le '
               + fin.toLocaleDateString('fr-FR') + '. Aucun prélèvement aujourd\'hui.'
      });
    }

    if (solde < prix) {
      return res.json({ ok: false, error: 'solde_insuffisant', total: prix, solde: solde });
    }

    // Référence unique : client + forfait + mois → double clic sans effet.
    const ref = 'FORFAIT-' + cli.id + '-' + cible + '-' + maintenant.toISOString().slice(0, 7);
    const { error: errRef } = await db.from('recharges').insert({
      client_id: cli.id, montant: -prix, moyen: 'forfait', statut: 'valide', reference: ref
    });
    if (errRef && errRef.code === '23505') {
      return res.json({ ok: false, error: 'deja_paye_ce_mois',
        message: 'Ce changement a déjà été réglé ce mois-ci.' });
    }
    if (errRef) { console.error('forfait ref error:', errRef.message);
      return res.json({ ok: false, error: 'insert_failed' }); }

    await db.from('clients').update({
      wallet_balance: solde - prix,
      offre: cible,
      abonnement_fin: nouvelleFin.toISOString(),
      offre_suivante: null
    }).eq('id', cli.id);

    const libelle = mode === 'montee_prorata'
      ? 'Montée en gamme ' + actuelle + ' vers ' + cible + ' (prorata '
        + detail.jours_restants + ' jours)'
      : 'Abonnement ' + cible + ' (payé via solde Tiinda)';
    emitInvoice(cli.id, libelle, prix, null).catch(function(){});

    res.json({
      ok: true, mode: mode, offre: cible, fin: nouvelleFin.toISOString(),
      debite: prix, solde: solde - prix, detail: detail
    });
  } catch (err) {
    console.error('forfait change-wallet error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Demande d'expédition (individuelle ou regroupée) — débite le wallet et notifie l'équipe.
app.post('/colis/expedier', requireAuth, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const phone = req.clientPhone;
    const { data: cli } = await db.from('clients').select('id, prenom, email, wallet_balance').eq('phone', phone).limit(1).maybeSingle();
    if (!cli) return res.json({ ok: false, error: 'client_not_found' });
    const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
    if (!ids.length) return res.json({ ok: false, error: 'aucun_colis' });
    // Récupère les colis du client, à l'état "reçu", avec un prix.
    const { data: colis } = await db.from('colis').select('*').eq('client_id', cli.id).in('id', ids);
    const list = (colis || []).filter(function (c) { return c.statut === 'recu'; });
    if (!list.length) return res.json({ ok: false, error: 'aucun_colis_eligible' });
    if (list.length !== ids.length) {
      return res.json({ ok: false, error: 'colis_deja_expedies',
        message: 'Un ou plusieurs colis ont déjà été expédiés.' });
    }
    // Frais par colis : valeur stockée, sinon recalcul (poids + dimensions).
    const fraisColis = function (c) {
      if (Number(c.frais_envoi || 0) > 0) return Number(c.frais_envoi);
      const kg = Number(c.poids || 0);
      const Lc = Number(c.longueur || 0), Wc = Number(c.largeur || 0), Hc = Number(c.hauteur || 0);
      if (!kg) return 0;
      const pf = (Lc && Wc && Hc) ? Math.ceil(Math.max(kg, (Lc * Wc * Hc) / 1000 / 6.26)) : Math.ceil(kg);
      return pf * 15;
    };
    let total = 0; list.forEach(function (c) { total += fraisColis(c); });
    const groupe = list.length >= 2;
    if (groupe) total = Math.round(total * 0.9 * 100) / 100; // remise regroupement 10%
    // Refus si total nul (colis non mesuré → pas de prix).
    if (!(total > 0)) return res.json({ ok: false, error: 'prix_indisponible' });
    // Vérifie le solde wallet.
    if (Number(cli.wallet_balance || 0) < total) {
      return res.json({ ok: false, error: 'solde_insuffisant', total: total, solde: Number(cli.wallet_balance || 0) });
    }
    // Débite le wallet + journalise + marque les colis "à expédier".
    await db.from('clients').update({ wallet_balance: Number(cli.wallet_balance) - total }).eq('id', cli.id);
    const refExp = 'EXP-' + list.map(function (c) { return c.id; }).sort().join('-');
    const { error: errExp } = await db.from('recharges').insert({
      client_id: cli.id, montant: -total, moyen: 'expedition', statut: 'valide', reference: refExp
    });
    if (errExp && errExp.code === '23505') {
      await db.from('clients').update({ wallet_balance: Number(cli.wallet_balance) }).eq('id', cli.id);
      return res.json({ ok: false, error: 'expedition_deja_payee',
        message: 'Cette expédition a déjà été réglée.' });
    }
    // On ne marque que les colis encore "recu" : verrou contre le double clic.
    const { data: majColis } = await db.from('colis')
      .update({ statut: 'a_expedier' })
      .in('id', list.map(function (c) { return c.id; }))
      .eq('statut', 'recu')
      .select('id');
    if (!majColis || majColis.length !== list.length) {
      return res.json({ ok: false, error: 'colis_deja_expedies' });
    }
    /* Bon de préparation : l'étape Départ se pilote par ce numéro, pas par
       le numéro de suivi. Un picking = une demande d'expédition d'un client. */
    const d = new Date();
    const jour = String(d.getFullYear()).slice(2) + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
    const { count: dejaCeJour } = await db
      .from('colis')
      .select('picking', { count: 'exact', head: true })
      .like('picking', 'PK-' + jour + '-%');
    const picking = 'PK-' + jour + '-' + String((dejaCeJour || 0) + 1).padStart(3, '0');
    await db.from('colis').update({ picking: picking }).in('id', list.map(function (c) { return c.id; }));

    // Facture auto pour l'expédition.
    const ref = list.map(function (c) { return c.tracking_interne; }).join(', ');
    emitInvoice(cli.id, (groupe ? 'Expédition groupée (' + list.length + ' colis) vers le Congo' : 'Expédition ' + ref + ' vers le Congo'), total, ref).catch(function(){});
    res.json({ ok: true, total: total, groupe: groupe, count: list.length, picking: picking });
  } catch (err) {
    console.error('expedier error:', err.message);
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

/* ── Assistant Tiinda (Claude / Anthropic) — clé secrète côté serveur ───────
   Répond aux questions clients sur le service. Renvoie aussi escalate=true
   quand il vaut mieux passer à un conseiller humain (WhatsApp). */
const TIINDA_SYSTEM = "Tu es l'assistant virtuel de Tiinda, un service qui donne aux clients une adresse en France pour recevoir leurs achats en ligne (Amazon, Shein, Zara...), puis expédie les colis au Congo-Brazzaville et en RDC. Réponds en français, ton chaleureux et concis. Infos clés : tarif expédition vers le Congo = 15 EUR/kg (poids facturé = le plus élevé entre poids réel et poids volumétrique, 1 kg = 6,26 L). Le client déclare son colis avec le numéro de suivi du transporteur, reçoit un numéro de suivi Tiinda (TND...). Étapes : Reçu en France -> Expédié vers Congo -> Arrivé au Congo -> Disponible au retrait -> Retiré. Le client recharge son solde Tiinda (carte, PayPal ou code de recharge) pour payer les expéditions. Regroupement de plusieurs colis = -10%. Points relais selon la ville. Ne JAMAIS inventer d'infos (numéros de commande, soldes, statuts précis). Si la question concerne un litige, un remboursement, un problème de paiement, un colis perdu, ou que tu n'es pas sûr, invite poliment le client à contacter un conseiller humain.";
app.post('/chat', async (req, res) => {
  try {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) return res.json({ ok: false, error: 'no_key' });
    if (!rateLimit('chat:' + clientIp(req), 30, 300000)) return res.json({ ok: false, error: 'too_many_requests' });
    const msgs = Array.isArray(req.body.messages) ? req.body.messages.slice(-12) : [];
    const clean = msgs.filter(function (m) { return m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string'; })
      .map(function (m) { return { role: m.role, content: String(m.content).slice(0, 2000) }; });
    if (!clean.length) return res.json({ ok: false, error: 'empty' });
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 500, system: TIINDA_SYSTEM, messages: clean }),
    });
    const data = await r.json();
    if (!r.ok) { console.error('chat error:', r.status, JSON.stringify(data).slice(0, 300)); return res.json({ ok: false, error: 'ia_error' }); }
    const reply = (data.content && data.content[0] && data.content[0].text) ? data.content[0].text : '';
    const escalate = /conseiller|humain|whatsapp|litige|rembours|perdu|r\u00e9clamation/i.test(reply);
    res.json({ ok: true, reply: reply, escalate: escalate });
  } catch (err) {
    console.error('chat exception:', err.message);
    res.json({ ok: false, error: 'server_error' });
  }
});

// ── WhatsApp entrant (Twilio) : menu de tri + identification par numéro ──────
// Twilio appelle cette URL à chaque message WhatsApp reçu. On répond en TwiML.
const waState = new Map(); // état de conversation par numéro (en mémoire)
function twiml(msg) {
  const safe = String(msg).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return '<?xml version="1.0" encoding="UTF-8"?><Response><Message>' + safe + '</Message></Response>';
}
const WA_MENU =
  "👋 Bienvenue chez *TIINDA* — vos achats d'Europe livrés au Congo.\n\n" +
  "Répondez par un chiffre :\n" +
  "*1* — Je suis déjà client Tiinda\n" +
  "*2* — Je ne suis pas encore client\n" +
  "*3* — Parler à un conseiller\n" +
  "*4* — Suivre un colis";

// Journalise un contact entrant (WhatsApp/SMS/appel) en l'identifiant par numéro.
async function logIncoming(phone, canal, message) {
  if (!db || !phone) return;
  try {
    const { data: cli } = await db.from('clients').select('id, prenom, nom, tiinda_id, offre').eq('phone', phone).limit(1).maybeSingle();
    await db.from('messages').insert({
      phone: phone, canal: canal, message: (message || '').slice(0, 500),
      client_id: cli ? cli.id : null,
      tiinda_id: cli ? cli.tiinda_id : null,
      nom: cli ? ((cli.prenom || '') + ' ' + (cli.nom || '')).trim() : null,
      offre: cli ? cli.offre : null,
      is_client: !!cli,
    });
  } catch (e) { console.error('logIncoming error:', e.message); }
}

// ── SMS entrant (Twilio) : identification + log + réponse menu ──────────────
app.post('/sms/incoming', express.urlencoded({ extended: false }), async (req, res) => {
  res.set('Content-Type', 'text/xml');
  const from = String(req.body.From || '').trim();
  const bodyRaw = String(req.body.Body || '').trim();
  logIncoming(from, 'sms', bodyRaw).catch(function(){});
  res.send(twiml('Merci pour votre message. Pour une réponse rapide, contactez-nous sur WhatsApp ou via votre espace tiinda.com. — TIINDA'));
});

// ── Appel entrant (Twilio Voice) : identifie l'appelant + log + message ─────
app.post('/voice/incoming', express.urlencoded({ extended: false }), async (req, res) => {
  res.set('Content-Type', 'text/xml');
  const from = String(req.body.From || '').trim();
  let nom = '';
  if (db) {
    try { const { data: cli } = await db.from('clients').select('prenom, tiinda_id').eq('phone', from).limit(1).maybeSingle(); if (cli) nom = cli.prenom || ''; } catch (e) {}
  }
  logIncoming(from, 'appel', '').catch(function(){});
  const say = nom ? ('Bonjour ' + nom + ', bienvenue chez Tiinda. Un conseiller va vous répondre.') : 'Bienvenue chez Tiinda. Un conseiller va vous répondre.';
  res.send('<?xml version="1.0" encoding="UTF-8"?><Response><Say language="fr-FR">' + say.replace(/&/g, 'et') + '</Say></Response>');
});

// (ADMIN) Messagerie : contacts entrants identifiés (WhatsApp/SMS/appels).
app.get('/admin/messages', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data } = await db.from('messages').select('*').order('created_at', { ascending: false }).limit(100);
    res.json({ ok: true, messages: data || [] });
  } catch (err) {
    console.error('admin messages error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/whatsapp/incoming', express.urlencoded({ extended: false }), async (req, res) => {
  res.set('Content-Type', 'text/xml');
  try {
    const from = String(req.body.From || '').replace('whatsapp:', '').trim();
    const bodyRaw = String(req.body.Body || '').trim();
    logIncoming(from, 'whatsapp', bodyRaw).catch(function(){});
    const body = bodyRaw.toLowerCase();
    const st = waState.get(from) || { step: 'menu' };

    // Mots-clés pour revenir au menu à tout moment.
    if (['menu', 'accueil', 'bonjour', 'salut', 'start', 'hi', 'hello'].indexOf(body) >= 0) {
      waState.set(from, { step: 'menu' });
      return res.send(twiml(WA_MENU));
    }

    // 1) Premier contact → on montre le menu.
    if (st.step === 'menu' && !/^[1-4]$/.test(body)) {
      waState.set(from, { step: 'menu' });
      return res.send(twiml(WA_MENU));
    }

    // 2) Choix du menu.
    if (st.step === 'menu' && /^[1-4]$/.test(body)) {
      if (body === '1') {
        // Client : on tente de l'identifier par son numéro WhatsApp.
        if (db) {
          const cli = await findClientByPhone('prenom, nom, tiinda_id, offre, wallet_balance', from);
          if (cli) {
            waState.set(from, { step: 'chat', tiinda_id: cli.tiinda_id });
            return res.send(twiml('✅ Ravi de vous revoir, *' + (cli.prenom || 'cher client') + '* !\n'
              + 'Votre identifiant : *' + cli.tiinda_id + '*\n'
              + 'Forfait : ' + (cli.offre || '—') + ' · Solde : ' + Number(cli.wallet_balance || 0).toFixed(2) + ' €\n\n'
              + 'Comment puis-je vous aider ? (suivi de colis, expédition, recharge…)\nTapez *menu* pour revenir au tri.'));
          }
        }
        // Pas reconnu → on demande l'identifiant.
        waState.set(from, { step: 'await_id' });
        return res.send(twiml('Pour vous identifier, envoyez votre *identifiant Tiinda* (ex : TIINDA000248).'));
      }
      if (body === '2') {
        waState.set(from, { step: 'chat' });
        return res.send(twiml('🎉 Bienvenue ! Avec Tiinda, vous obtenez une *adresse en France* pour recevoir vos achats (Amazon, Shein, Zara…), puis nous les livrons au Congo.\n\n'
          + '👉 Créez votre compte : https://tiinda.com\n\n'
          + 'Une question ? Écrivez-la, je vous réponds. (Tapez *menu* pour le tri.)'));
      }
      if (body === '3') {
        waState.set(from, { step: 'human' });
        return res.send(twiml('🧑‍💼 Un conseiller Tiinda va vous répondre dès que possible (horaires 8h–20h, 7j/7).\n\nDécrivez votre demande en attendant.'));
      }
      if (body === '4') {
        waState.set(from, { step: 'await_track' });
        return res.send(twiml('📦 Envoyez votre *numéro de suivi Tiinda* (ex : TND123456789) pour connaître le statut de votre colis.'));
      }
    }

    // 3) Saisie de l'identifiant Tiinda.
    if (st.step === 'await_id') {
      const id = bodyRaw.toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (db && /^TIINDA\d+/.test(id)) {
        const { data: cli } = await db.from('clients').select('prenom, tiinda_id, offre, wallet_balance').eq('tiinda_id', id).limit(1).maybeSingle();
        if (cli) {
          waState.set(from, { step: 'chat', tiinda_id: cli.tiinda_id });
          return res.send(twiml('✅ Identifié : *' + (cli.prenom || 'client') + '* (' + cli.tiinda_id + ')\n'
            + 'Forfait : ' + (cli.offre || '—') + ' · Solde : ' + Number(cli.wallet_balance || 0).toFixed(2) + ' €\n\n'
            + 'Comment puis-je vous aider ?'));
        }
      }
      return res.send(twiml('❌ Identifiant introuvable. Vérifiez le format (TIINDA…) ou tapez *menu*.'));
    }

    // 4) Suivi d'un colis.
    if (st.step === 'await_track') {
      const code = bodyRaw.toUpperCase().replace(/[^A-Z0-9\-]/g, '');
      if (db && code) {
        const { data: c } = await db.from('colis').select('tracking_interne, statut, description')
          .or('tracking_interne.eq.' + code + ',tracking_externe.eq.' + code).limit(1).maybeSingle();
        if (c) {
          const L = { declare: 'Déclaré', recu: 'Reçu à notre entrepôt en France', a_expedier: 'Expédition demandée', expedie: 'En route vers le Congo', arrive: 'Arrivé au Congo', disponible: 'Disponible au retrait', livre: 'Retiré' };
          return res.send(twiml('📦 *' + c.tracking_interne + '*\n' + (c.description ? c.description + '\n' : '') + 'Statut : *' + (L[c.statut] || c.statut) + '*\n\nTapez *menu* pour revenir.'));
        }
      }
      return res.send(twiml('Colis introuvable. Vérifiez le numéro (TND…) ou tapez *menu*.'));
    }

    // 5) Sinon → assistant IA (Claude), avec contexte client si connu.
    const key = process.env.ANTHROPIC_API_KEY;
    if (key && rateLimit('wa:' + from, 60, 300000)) {
      const ctx = st.tiinda_id ? ('Le client est identifié, identifiant Tiinda ' + st.tiinda_id + '. ') : '';
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 400, system: ctx + TIINDA_SYSTEM, messages: [{ role: 'user', content: bodyRaw.slice(0, 1000) }] }),
      });
      const data = await r.json();
      const reply = (r.ok && data.content && data.content[0] && data.content[0].text) ? data.content[0].text : 'Désolé, je n\'ai pas compris. Tapez *menu* pour revenir au tri.';
      return res.send(twiml(reply));
    }
    return res.send(twiml('Tapez *menu* pour afficher les options.'));
  } catch (err) {
    console.error('whatsapp incoming error:', err.message);
    return res.send(twiml('Une erreur est survenue. Tapez *menu* pour réessayer.'));
  }
});

// (EMPLOYÉ) Statistiques rapides de l'entrepôt — comptage par statut.
app.get('/scan/stats', requireScan, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data } = await db.from('colis').select('statut, created_at');
    const co = data || [];
    const by = {};
    const dayStart = new Date(); dayStart.setHours(0, 0, 0, 0);
    let today = 0;
    co.forEach(function (c) {
      by[c.statut || 'declare'] = (by[c.statut || 'declare'] || 0) + 1;
      if (c.created_at && new Date(c.created_at) >= dayStart) today++;
    });
    res.json({ ok: true, total: co.length, today: today, byStatut: by });
  } catch (err) {
    console.error('scan stats error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true, db: !!db, track123: !!TRACK123_API_KEY }));

/* ── Compteur de visites (visiteurs journaliers) ───────────────────────────
   Appelé par le site à chaque visite. Incrémente le compteur du jour dans la
   table `visites` (jour unique). Sans auth (public), tolérant aux erreurs. */
app.post('/visite', async (req, res) => {
  try {
    if (!db) return res.json({ ok: true });
    const jour = new Date().toISOString().slice(0, 10);
    const { data: row } = await db.from('visites').select('count').eq('jour', jour).maybeSingle();
    if (row) await db.from('visites').update({ count: Number(row.count || 0) + 1 }).eq('jour', jour);
    else await db.from('visites').insert({ jour: jour, count: 1 });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: true }); }
});

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

/* ── Verrou d'ordre du parcours colis ──────────────────────────────────────
   Un scan ne peut que faire AVANCER le colis. Retour en arrière ou re-scan
   de la même étape : refusé, et le client n'est pas notifié. Un responsable
   peut forcer avec le code SCAN_OVERRIDE_CODE (variable d'environnement). */
const SCAN_ORDER = { declare: 0, recu: 1, a_expedier: 1, expedie: 2, arrive: 3, disponible: 4, livre: 5 };
function scanRank(s) {
  const r = SCAN_ORDER[String(s || '').toLowerCase()];
  return r === undefined ? -1 : r;
}
const SCAN_OVERRIDE_CODE = process.env.SCAN_OVERRIDE_CODE || '';
function scanForced(b) {
  return !!SCAN_OVERRIDE_CODE && String((b && b.override_code) || '') === SCAN_OVERRIDE_CODE;
}

/* Le dépôt de Drancy traite les deux marques du groupe Colispo.
   Le préfixe du numéro suffit à savoir où chercher :
     TND… → table « colis »           (Tiinda, Congo)
     CLB… → table « envois_coolibo »  (Coolibo, France)
   Le PDA n'a donc qu'un seul champ de scan, et l'opérateur ne choisit rien. */
const estCoolibo = (code) => /^CLB/i.test(String(code || '').trim());
const tableDe = (code) => (estCoolibo(code) ? 'envois_coolibo' : 'colis');

/* Un casier ne peut contenir qu'un colis, quelle que soit la marque :
   l'occupation se lit dans les deux tables à la fois. */
async function casiersPris() {
  const pris = new Map();
  const lots = await Promise.all([
    db.from('colis').select('emplacement, tracking_interne')
      .not('emplacement', 'is', null).in('statut', ['recu', 'a_expedier']),
    db.from('envois_coolibo').select('emplacement, tracking_interne')
      .not('emplacement', 'is', null).in('statut', ['recu', 'a_expedier']),
  ]);
  lots.forEach(({ data }) => (data || []).forEach((r) => {
    const e = String(r.emplacement || '').toUpperCase();
    if (!e || /^CONT-/.test(e)) return;   // zone conteneur : plusieurs colis admis
    pris.set(e, r.tracking_interne);
  }));
  return pris;
}

// (EMPLOYÉ) Recherche d'un colis par numéro → statut + infos (lecture seule).
app.get('/scan/lookup', requireScan, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const code = String(req.query.q || '').trim().toUpperCase().replace(/[^A-Z0-9\-]/g, '');
    if (!code) return res.json({ ok: false, error: 'missing' });

    if (estCoolibo(code)) {
      const { data: e } = await db.from('envois_coolibo').select('*')
        .or('tracking_interne.eq.' + code + ',tracking_externe.eq.' + code).limit(1).maybeSingle();
      if (!e) return res.json({ ok: false, error: 'colis_introuvable' });
      const dom = e.mode === 'domicile';
      return res.json({
        ok: true,
        marque: 'coolibo',
        colis: {
          tracking_interne: e.tracking_interne, tracking_externe: e.tracking_externe || '',
          statut: e.statut, type_colis: e.type_colis || 'carton',
          description: e.description || (e.carton ? ('Envoi Coolibo · ' + e.carton) : 'Envoi Coolibo'),
          poids: e.poids, longueur: e.longueur, largeur: e.largeur, hauteur: e.hauteur,
          frais_envoi: e.frais_envoi, emplacement: e.emplacement || null, picking: e.picking || null,
          received_at: e.received_at || null, created_at: e.created_at,
        },
        client: {
          nom: e.dest_nom || e.email || '',
          tiinda_id: dom ? 'Coolibo · domicile' : 'Coolibo · point relais',
          phone: e.dest_phone || '',
          ville: [e.zip, e.ville].filter(Boolean).join(' '),
        },
        destination: {
          ville: e.dest_ville || '', quartier: e.dest_quartier || '',
          mode: e.dest_mode || '', nom: e.dest_nom || '', phone: e.dest_phone || '',
        },
      });
    }

    const { data: c } = await db.from('colis').select('tracking_interne, tracking_externe, statut, description, type_colis, poids, longueur, largeur, hauteur, frais_envoi, emplacement, picking, received_at, created_at, client_id')
      .or('tracking_interne.eq.' + code + ',tracking_externe.eq.' + code).limit(1).maybeSingle();
    if (!c) return res.json({ ok: false, error: 'colis_introuvable' });
    let client = null;
    if (c.client_id) {
      const { data: cli } = await db.from('clients').select('prenom, nom, tiinda_id, phone, ville').eq('id', c.client_id).maybeSingle();
      if (cli) client = { nom: ((cli.prenom||'')+' '+(cli.nom||'')).trim(), tiinda_id: cli.tiinda_id, phone: cli.phone, ville: cli.ville };
    }
    res.json({ ok: true, colis: c, client: client });
  } catch (err) {
    console.error('scan lookup error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ── Attribution automatique d'une place ──────────────────────────────────
   Dépôt Drancy : 5 allées (A→E) × 5 rayonnages × 5 étages × 4 places = 500.
   Code : ALLEE-RAYONNAGE-ETAGEPLACE, ex. « B-03-42 » (étage 4, place 2).
   L'employé ne choisit pas : le serveur propose la première place libre
   adaptée au poids et au type, l'employé scanne le code-barres du casier. */
const DEPOT = { allees: ['B', 'C', 'D'], rayonnages: 5, etages: 5, places: 4 };
const ALLEE_HORS_GABARIT = 'E';

function etagesPreferes(poidsKg, type) {
  const p = Number(poidsKg) || 0;
  if (p > 15) return [1, 2];                       // lourd : au sol
  if (type === 'sac' || type === 'enveloppe') return [5, 4, 3];
  if (p < 5) return [4, 3, 5, 2];
  return [3, 2, 4, 1, 5];
}
function placesCandidates(poidsKg, type) {
  const out = [];
  const etages = etagesPreferes(poidsKg, type);
  const allees = (Number(poidsKg) || 0) > 60 ? [ALLEE_HORS_GABARIT] : DEPOT.allees;
  for (const et of etages)
    for (const al of allees)
      for (let ray = 1; ray <= DEPOT.rayonnages; ray++)
        for (let pl = 1; pl <= DEPOT.places; pl++)
          out.push(`${al}-${String(ray).padStart(2, '0')}-${et}${pl}`);
  return out;
}
const ETAGE_LIB = { 1: 'étage 1 — au sol', 2: 'étage 2', 3: 'étage 3 — hauteur des yeux', 4: 'étage 4', 5: 'étage 5 — en haut' };

/* Conteneur maritime Coolibo : trois zones, une par ville desservie.
   Un colis Coolibo ne va jamais au rayonnage — il part dans le conteneur,
   dans la zone de sa ville de destination. Une zone accueille des dizaines
   de colis : pas d'unicité à vérifier, contrairement aux casiers Tiinda. */
const ZONES_COOLIBO = {
  'POINTE-NOIRE': { code: 'CONT-PNR', nom: 'Pointe-Noire' },
  'DOLISIE':      { code: 'CONT-DLS', nom: 'Dolisie' },
  'BRAZZAVILLE':  { code: 'CONT-BZV', nom: 'Brazzaville' },
};
function zoneCoolibo(ville) {
  const v = String(ville || '').trim().toUpperCase().replace(/\s+/g, '-');
  return ZONES_COOLIBO[v] || null;
}

app.get('/admin/place/next', requireScan, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const poids = req.query.poids;

    const codeQ = String(req.query.code || '').trim().toUpperCase();
    if (estCoolibo(codeQ)) {
      const { data: e } = await db.from('envois_coolibo').select('dest_ville, tracking_interne')
        .eq('tracking_interne', codeQ).limit(1).maybeSingle();
      const z = zoneCoolibo(e && e.dest_ville);
      if (!z) return res.json({ ok: false, error: 'destination_inconnue' });
      return res.json({
        ok: true,
        emplacement: z.code,
        detail: 'Conteneur · zone ' + z.nom,
        zone: z.nom,
      });
    }
    const type = String(req.query.type || '');
    const exclure = String(req.query.exclure || '').toUpperCase();

    // Places déjà occupées : colis encore physiquement au dépôt (Tiinda + Coolibo).
    const prises = new Set((await casiersPris()).keys());
    if (exclure) prises.add(exclure);

    /* Pas de quarantaine par défaut : un casier vidé se réutilise aussitôt.
       Mettre PLACE_QUARANTAINE_H sur Render pour en imposer une. */
    const QUARANTAINE_H = Number(process.env.PLACE_QUARANTAINE_H || 0);
    if (QUARANTAINE_H > 0) {
      const depuis = new Date(Date.now() - QUARANTAINE_H * 3600 * 1000).toISOString();
      const { data: recents } = await db
        .from('colis')
        .select('emplacement_prec')
        .not('emplacement_prec', 'is', null)
        .gte('libere_le', depuis);
      (recents || []).forEach((r) => prises.add(String(r.emplacement_prec || '').toUpperCase()));
    }

    const cand = placesCandidates(poids, type);
    const libre = cand.find((c) => !prises.has(c));
    const total = DEPOT.allees.length * DEPOT.rayonnages * DEPOT.etages * DEPOT.places;
    if (!libre) return res.json({ ok: false, error: 'depot_plein' });

    const et = Number(libre.slice(-2, -1));
    res.json({
      ok: true,
      emplacement: libre,
      detail: `Allée ${libre[0]} · rayonnage ${libre.slice(2, 4)} · ${ETAGE_LIB[et]}`,
      restantes: Math.max(0, total - prises.size),
    });
  } catch (e) {
    res.json({ ok: false, error: 'exception' });
  }
});

/* Le client reçoit son étiquette dès l'encaissement : un lien par colis,
   plus la marche à suivre selon son mode d'envoi. */
async function envoyerEtiquetteCoolibo(email, lignes) {
  if (!RESEND_API_KEY || !email || !lignes || !lignes.length) return;
  const base = (process.env.SITE_URL || 'https://tiinda-otp.onrender.com').replace(/\/$/, '');
  const relais = lignes[0].mode === 'relais';
  const boutons = lignes.map((l) =>
    '<div style="margin:10px 0"><a href="' + base + '/coolibo/etiquette/' + l.tracking_interne + '"'
    + ' style="display:inline-block;background:#0B2A5B;color:#fff;text-decoration:none;'
    + 'padding:14px 24px;border-radius:10px;font-weight:700">Imprimer l\u2019étiquette '
    + l.tracking_interne + '</a></div>').join('');
  const suite = relais
    ? '<p style="color:#42556f;line-height:1.6">Collez l\u2019étiquette sur votre colis, puis déposez-le '
      + 'dans votre point relais Mondial Relay avec l\u2019étiquette transporteur que vous recevrez séparément.</p>'
    : '<p style="color:#42556f;line-height:1.6">Collez l\u2019étiquette sur votre colis. Notre équipe vient '
      + 'le récupérer à l\u2019adresse indiquée, au créneau que vous choisirez.</p>';
  const html = '<div style="font-family:Arial,Helvetica,sans-serif;max-width:540px;margin:auto;color:#16243d">'
    + '<div style="background:#0B2A5B;color:#fff;padding:20px;border-radius:12px 12px 0 0">'
    + '<strong style="font-size:19px">Coolibo · votre envoi est confirmé</strong></div>'
    + '<div style="border:1px solid #e3e7ef;border-top:none;border-radius:0 0 12px 12px;padding:22px">'
    + '<p style="margin-top:0;color:#42556f;line-height:1.6">Merci, votre paiement est bien reçu. '
    + 'Voici votre étiquette à imprimer et à coller sur le colis.</p>'
    + boutons + suite
    + '<p style="color:#8a97ad;font-size:13px;margin-bottom:0">Conservez ce message : le lien reste valable '
    + 'jusqu\u2019à la livraison.</p></div></div>';
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: MAIL_FROM || 'Coolibo <onboarding@resend.dev>', to: email,
        subject: 'Coolibo · votre étiquette (' + lignes.map((l) => l.tracking_interne).join(', ') + ')',
        html,
      }),
    });
  } catch (e) { console.error('coolibo mail error:', e.message); }
}

/* ── Étiquette Coolibo à imprimer par le client ───────────────────────────
   Servie directement par le serveur : le numéro CLB fait office de clé, il
   n'est connu que du client qui a payé. Page A4, prête à imprimer, à coller
   sur le colis avant dépôt en point relais ou enlèvement à domicile. */
const C128_TBL = ('212222 222122 222221 121223 121322 131222 122213 122312 132212 221213 ' +
  '221312 231212 112232 122132 122231 113222 123122 123221 223211 221132 221231 ' +
  '213212 223112 312131 311222 321122 321221 312212 322112 322211 212123 212321 ' +
  '232121 111323 131123 131321 112313 132113 132311 211313 231113 231311 112133 ' +
  '112331 132131 113123 113321 133121 313121 211331 231131 213113 213311 213131 ' +
  '311123 311321 331121 312113 312311 332111 314111 221411 431111 111224 111422 ' +
  '121124 121421 141122 141221 112214 112412 122114 122411 142112 142211 241211 ' +
  '221114 413111 241112 134111 111242 121142 121241 114212 124112 124211 411212 ' +
  '421112 421211 212141 214121 412121 111143 111341 131141 114113 114311 411113 ' +
  '411311 113141 114131 311141 411131 211412 211214 211232 2331112').split(' ');

function barresSVG(txt, wmm, hmm) {
  const codes = [104];
  for (let i = 0; i < txt.length; i++) codes.push(txt.charCodeAt(i) - 32);
  let som = 104;
  for (let i = 1; i < codes.length; i++) som += codes[i] * i;
  codes.push(som % 103); codes.push(106);
  const m = codes.map((c) => C128_TBL[c]).join('');
  let tot = 0; for (const ch of m) tot += +ch;
  let x = 0, out = '';
  for (let i = 0; i < m.length; i++) {
    const w = +m[i];
    if (i % 2 === 0) out += `<rect x="${x}" y="0" width="${w}" height="100" fill="#000"/>`;
    x += w;
  }
  return `<svg viewBox="0 0 ${tot} 100" preserveAspectRatio="none" style="width:${wmm}mm;height:${hmm}mm;display:block">${out}</svg>`;
}

const htmlEsc = (t) => String(t == null ? '' : t)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

app.get('/coolibo/etiquette/:code', async (req, res) => {
  try {
    const code = String(req.params.code || '').trim().toUpperCase().replace(/[^A-Z0-9-]/g, '');
    if (!db || !/^CLB-\d{4}-[A-Z0-9]{6}$/.test(code)) return res.status(404).send('Étiquette introuvable.');
    const { data: e } = await db.from('envois_coolibo').select('*')
      .eq('tracking_interne', code).limit(1).maybeSingle();
    if (!e) return res.status(404).send('Étiquette introuvable.');

    const relais = e.mode === 'relais';
    const consigne = relais
      ? 'Collez cette étiquette sur le colis, puis déposez-le dans votre point relais Mondial Relay avec l’étiquette transporteur.'
      : 'Collez cette étiquette sur le colis. Notre équipe vient le récupérer à l’adresse indiquée, au créneau que vous avez choisi.';
    const dFR = (v) => { try { return new Date(v).toLocaleDateString('fr-FR',
      { day: '2-digit', month: '2-digit', year: 'numeric' }); } catch (e) { return ''; } };
    const emiseLe = dFR(e.created_at || Date.now());
    const ligne = (k, v) => `<tr><td style="padding:2mm 0;color:#6a7891;font-size:10pt;width:38mm">${htmlEsc(k)}</td>
      <td style="padding:2mm 0;font-size:12pt;font-weight:700">${htmlEsc(v || '—')}</td></tr>`;

    res.set('Content-Type', 'text/html; charset=utf-8').send(`<!doctype html><html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Étiquette ${code} · Coolibo</title><style>
  @page{size:A4 portrait;margin:0}
  *{box-sizing:border-box;font-family:Arial,Helvetica,sans-serif;color:#000}
  body{margin:0;background:#eef0f5;display:flex;flex-direction:column;align-items:center;padding:18px;gap:14px}
  .barre{width:210mm;display:flex;justify-content:space-between;align-items:center;gap:14px}
  .barre b{font-size:16px}.barre p{margin:2px 0 0;font-size:13px;color:#42556f}
  button{background:#0B2A5B;color:#fff;border:none;border-radius:10px;padding:13px 22px;
    font-size:14px;font-weight:800;cursor:pointer}
  .page{width:210mm;min-height:297mm;background:#fff;padding:18mm 16mm;box-shadow:0 14px 40px rgba(0,0,0,.18)}
  .etq{border:0.8mm dashed #0B2A5B;border-radius:3mm;padding:8mm}
  .cut{font-size:9pt;color:#8a97ad;margin:0 0 3mm}
  @media print{body{background:#fff;padding:0;gap:0}.barre{display:none}
    .page{box-shadow:none;width:auto;min-height:auto;padding:14mm}}
</style></head><body>
<div class="barre">
  <div><b>Étiquette Coolibo · ${code}</b><p>Imprimez cette page, découpez le cadre et collez-le sur le colis.</p></div>
  <button onclick="window.print()">Imprimer</button>
</div>
<div class="page">
  <p class="cut">✂ Découpez le long du cadre</p>
  <div class="etq">
    <div style="display:flex;align-items:center;justify-content:space-between;border-bottom:0.8mm solid #000;padding-bottom:4mm">
      <span style="font-size:22pt;font-weight:800;letter-spacing:-.02em">Coolibo</span>
      <span style="font-size:10pt;font-weight:700;border:0.5mm solid #000;padding:1.5mm 4mm">
        ${relais ? 'POINT RELAIS' : 'ENLÈVEMENT À DOMICILE'}</span>
    </div>

    <div style="padding:6mm 0 4mm;border-bottom:0.4mm solid #000">
      <div style="font-size:9pt;color:#6a7891;text-transform:uppercase;letter-spacing:.08em">Destination</div>
      <div style="font-size:30pt;font-weight:800;line-height:1.05;letter-spacing:-.02em">
        ${htmlEsc(e.dest_ville || 'Congo')}</div>
      <div style="font-size:12pt;font-weight:700;margin-top:1mm">${htmlEsc(e.dest_nom || '')}
        ${e.dest_phone ? ' · ' + htmlEsc(e.dest_phone) : ''}</div>
    </div>

    <table style="width:100%;border-collapse:collapse;margin:3mm 0">
      ${ligne('Expéditeur', e.email || '')}
      ${ligne('Enlèvement', [e.zip, e.ville].filter(Boolean).join(' '))}
      ${ligne('Format', e.carton || '—')}
      ${ligne('Émise le', emiseLe)}
      ${ligne('Remise', e.dest_mode === 'domicile' ? ('Livraison à domicile' + (e.dest_quartier ? ' · ' + e.dest_quartier : '')) : 'Retrait à l’agence')}
    </table>

    <div style="display:flex;flex-direction:column;align-items:center;gap:2mm;border-top:0.4mm solid #000;padding-top:5mm">
      ${barresSVG(code, 120, 26)}
      <span style="font-family:monospace;font-size:17pt;font-weight:700;letter-spacing:.14em">${code}</span>
      <span style="font-size:9pt;color:#6a7891">Dépôt Colispo · 3 rue de la Butte, 93700 Drancy</span>
    </div>
  </div>
  <p style="font-size:11pt;line-height:1.6;color:#42556f;margin:8mm 0 0">${consigne}</p>
</div>
</body></html>`);
  } catch (e) {
    res.status(500).send('Erreur.');
  }
});

/* (CLIENT) Numéros de suivi Coolibo d'une commande, après paiement.
   Permet à la page de confirmation d'afficher les CLB générés par le webhook. */
app.get('/coolibo/commande/:ref', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const ref = 'SHOP-' + String(req.params.ref || '').replace(/[^0-9]/g, '');
    if (ref === 'SHOP-') return res.json({ ok: false, error: 'params' });
    const { data } = await db.from('envois_coolibo')
      .select('tracking_interne, mode, ville, frais_envoi, statut')
      .eq('shopify_order', ref)
      .order('tracking_interne', { ascending: true });
    res.json({ ok: true, envois: data || [] });
  } catch (e) {
    res.json({ ok: false, error: 'exception' });
  }
});

/* (EMPLOYÉ) Bons de préparation en attente — le poste Départ de Drancy les
   affiche et imprime automatiquement les nouveaux. */
/* Bons en attente : uniquement ceux dont il reste des colis à sortir.
   Un bon entièrement expédié disparaît et ne peut plus être rouvert. */
app.get('/admin/picking/pending', requireScan, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: rows } = await db.from('colis')
      .select('picking, client_id, emplacement')
      .eq('statut', 'a_expedier')
      .not('picking', 'is', null);
    if (!rows || !rows.length) return res.json({ ok: true, pickings: [] });

    const par = new Map();
    for (const r of rows) {
      const g = par.get(r.picking) || { picking: r.picking, client_id: r.client_id, colis: 0, places: [] };
      g.colis++; if (r.emplacement) g.places.push(r.emplacement);
      par.set(r.picking, g);
    }
    const ids = [...new Set(rows.map((r) => r.client_id))];
    const { data: cls } = await db.from('clients').select('id, prenom, nom, ville').in('id', ids);
    const nom = new Map((cls || []).map((c) => [c.id, [c.prenom, c.nom].filter(Boolean).join(' ')]));

    res.json({
      ok: true,
      pickings: [...par.values()]
        .sort((a, b) => a.picking.localeCompare(b.picking))
        .map((g) => ({ picking: g.picking, colis: g.colis, client: nom.get(g.client_id) || '—', places: g.places.sort() })),
    });
  } catch (e) {
    res.json({ ok: false, error: 'exception' });
  }
});

/* (EMPLOYÉ) Bon de préparation : liste les colis à aller chercher, avec
   leur emplacement dans le dépôt. Accepte le n° de picking OU un n° de colis. */
app.get('/admin/picking', requireScan, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    let num = String(req.query.q || '').trim().toUpperCase();
    if (!num) return res.json({ ok: false, error: 'params' });

    if (!/^PK-/.test(num)) {
      const { data: un } = await db.from('colis').select('picking')
        .or(`tracking_interne.eq.${num},tracking_externe.eq.${num}`).limit(1).maybeSingle();
      if (!un || !un.picking) return res.json({ ok: false, error: 'pas_de_picking' });
      num = un.picking;
    }

    const { data: colis } = await db.from('colis')
      .select('tracking_interne, description, poids, longueur, largeur, hauteur, type_colis, emplacement, statut, client_id, picking')
      .eq('picking', num)
      .order('emplacement', { ascending: true });
    if (!colis || !colis.length) return res.json({ ok: false, error: 'picking_introuvable' });

    const { data: cl } = await db.from('clients')
      .select('prenom, nom, tiinda_id, offre, phone, ville, commune, rue, repere')
      .eq('id', colis[0].client_id).maybeSingle();

    res.json({
      ok: true,
      picking: num,
      statut: colis.some((c) => c.statut === 'a_expedier') ? 'a_preparer' : 'traite',
      client: cl || {},
      colis: colis.map((c, i) => ({
        code: c.tracking_interne, emplacement: c.emplacement, description: c.description,
        poids: c.poids, type_colis: c.type_colis, statut: c.statut,
        dims: [c.longueur, c.largeur, c.hauteur].filter(Boolean).join('×'),
        rang: i + 1, total: colis.length,
      })),
    });
  } catch (e) {
    res.json({ ok: false, error: 'exception' });
  }
});

/* Rangement seul : le colis est déjà reçu et pesé, on n'enregistre que
   l'emplacement dans le dépôt (ex. « B-04-12 »). Aucune notification client. */
app.post('/admin/ranger', requireScan, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    const code = String(b.code || '').trim();
    const emplacement = String(b.emplacement || '').trim().toUpperCase().slice(0, 12);
    if (!code || !emplacement) return res.json({ ok: false, error: 'params' });

    const table = tableDe(code);
    const { data: colis } = await db
      .from(table)
      .select('id, tracking_interne, statut, emplacement')
      .or(`tracking_interne.eq.${code},tracking_externe.eq.${code}`)
      .maybeSingle();
    if (!colis) return res.json({ ok: false, error: 'colis_introuvable' });

    if (!/^CONT-/.test(emplacement)) {
      const occupant = (await casiersPris()).get(emplacement);
      if (occupant && occupant !== colis.tracking_interne) {
        return res.json({ ok: false, error: 'casier_occupe', par: occupant });
      }
    }

    const { error } = await db.from(table).update({ emplacement }).eq('id', colis.id);
    if (error) return res.json({ ok: false, error: 'db' });
    res.json({ ok: true, emplacement, tracking_interne: colis.tracking_interne });
  } catch (e) {
    res.json({ ok: false, error: 'exception' });
  }
});

// Réception & mesure : enregistre type, dimensions, poids → transmis admin + client.
app.post('/admin/measure', requireScan, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    const code = String(b.code || '').trim().toUpperCase().replace(/[^A-Z0-9\-]/g, '');
    if (!code) return res.json({ ok: false, error: 'missing' });
    const table = tableDe(code);
    const { data: colis } = await db.from(table).select('*')
      .or('tracking_interne.eq.' + code + ',tracking_externe.eq.' + code).limit(1).maybeSingle();
    if (!colis) return res.json({ ok: false, error: 'colis_introuvable' });
    // Bloque la double réception/mesure (sauf code responsable).
    if ((colis.statut === 'recu' || colis.received_at) && !scanForced(b)) {
      return res.json({ ok: false, error: 'deja_mesure', recu_le: colis.received_at || null, statut_actuel: colis.statut });
    }
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
    /* Poids annoncé par le client à la commande : on le fige avant que la
       pesée ne l'écrase, et on enregistre l'écart. Aucune refacturation
       automatique — l'administrateur tranche depuis le tableau de bord. */
    const decl = (colis.poids_declare != null) ? Number(colis.poids_declare)
               : (colis.poids != null ? Number(colis.poids) : null);
    if (colis.poids_declare == null && decl != null) patch.poids_declare = decl;
    if (decl != null && kg != null) {
      const e = Math.round((kg - decl) * 100) / 100;
      patch.ecart_poids = e;
      if (Math.abs(e) > 0.5) {
        console.warn('écart de poids', colis.tracking_interne, 'déclaré', decl, '→ pesé', kg, '(' + e + ' kg)');
      }
    }
    /* Coolibo achemine en France : le prix est déjà payé à la commande,
       la pesée à Drancy ne le recalcule pas. */
    if (frais != null && !estCoolibo(code)) patch.frais_envoi = frais;
    if (b.description) patch.description = b.description;
    if (b.emplacement) {
      const empl = String(b.emplacement).trim().toUpperCase().slice(0, 12);
      if (!/^CONT-/.test(empl)) {
        const occupant = (await casiersPris()).get(empl);
        if (occupant && occupant !== colis.tracking_interne) {
          return res.json({ ok: false, error: 'casier_occupe', par: occupant });
        }
      }
      patch.emplacement = empl;
    }
    const { data, error } = await db.from(table).update(patch).eq('id', colis.id).select().single();
    if (error) { console.error('measure error:', error.message); return res.json({ ok: false, error: 'update_failed' }); }
    // Notifie le client (colis reçu + mesuré + prix d'expédition).
    if (colis.statut !== 'recu' && colis.client_id) notifyColisStatus(colis.client_id, data).catch(function(){});
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
    const table = tableDe(code);
    const { data: colis } = await db.from(table).select('*')
      .or('tracking_interne.eq.' + code + ',tracking_externe.eq.' + code).limit(1).maybeSingle();
    if (!colis) return res.json({ ok: false, error: 'colis_introuvable' });
    // Verrou d'ordre : ni retour en arrière, ni re-scan de la même étape.
    {
      const rc = scanRank(colis.statut), rt = scanRank(statut);
      if (rc >= 0 && rt >= 0 && rc >= rt && !scanForced(b)) {
        return res.json({
          ok: false,
          error: rc === rt ? 'deja_scanne' : 'ordre_invalide',
          statut: statut,
          statut_actuel: colis.statut,
        });
      }
      if (scanForced(b)) console.warn('scan forcé:', colis.tracking_interne, colis.statut, '->', statut);
    }
    const patch = { statut: statut };
    if (statut === 'recu') patch.received_at = new Date().toISOString();
    /* Place libérée dès que le colis quitte le dépôt France. On garde l'ancien
       casier et l'heure : il reste en quarantaine quelques heures pour ne pas
       être réattribué à un colis pendant qu'on le sort encore du rayonnage. */
    if (['expedie', 'arrive', 'disponible', 'livre'].includes(statut) && colis.emplacement) {
      patch.emplacement = null;
      patch.emplacement_prec = colis.emplacement;
      patch.libere_le = new Date().toISOString();
    }
    if (b.signature_url) patch.signature_url = b.signature_url;
    if (b.photo_url) patch.photo_url = b.photo_url;
    const { data, error } = await db.from(table).update(patch).eq('id', colis.id).select().single();
    if (error) { console.error('scan update error:', error.message); return res.json({ ok: false, error: 'update_failed' }); }
    if (colis.statut !== statut && colis.client_id) notifyColisStatus(colis.client_id, data).catch(function(){});
    // Émission auto de facture quand le colis part vers le Congo (frais d'envoi connus).
    if (!estCoolibo(code) && statut === 'expedie' && data.frais_envoi && colis.statut !== 'expedie') {
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

// Rapports & analyses : CA par source, acquisition, top marchands, recharges.
app.get('/admin/reports', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: colis } = await db.from('colis').select('site_marchand, poids, valeur, frais_envoi, created_at');
    const { data: rech } = await db.from('recharges').select('montant, moyen');
    const { data: cl } = await db.from('clients').select('offre, acq_source, created_at');
    const co = colis || [], rc = rech || [], cls = cl || [];
    const PRICES = { bokolo: 9.99, familia: 19.90, mokili: 49.90 };
    const norm = function (s) { s = (s || '').toLowerCase(); return s.indexOf('mokili') >= 0 ? 'mokili' : s.indexOf('familia') >= 0 ? 'familia' : 'bokolo'; };
    // CA par source
    let abos = 0; cls.forEach(function (c) { abos += PRICES[norm(c.offre)]; });
    let frais = 0; co.forEach(function (c) { frais += Number(c.frais_envoi || 0); });
    let codes = 0; rc.forEach(function (r) { if (r.moyen === 'code' && Number(r.montant) > 0) codes += Number(r.montant); });
    // Top marchands
    const merch = {}; co.forEach(function (c) { const m = (c.site_marchand || 'Autre').trim() || 'Autre'; merch[m] = (merch[m] || 0) + 1; });
    // Acquisition
    const acq = {}; cls.forEach(function (c) { const a = c.acq_source || 'non renseigné'; acq[a] = (acq[a] || 0) + 1; });
    // Recharges par moyen
    const rechMoyen = {}; rc.forEach(function (r) { if (Number(r.montant) > 0) { const m = r.moyen || 'autre'; rechMoyen[m] = (rechMoyen[m] || 0) + Number(r.montant); } });
    // Moyennes colis
    let pSum = 0, pN = 0, vSum = 0, vN = 0; co.forEach(function (c) { if (c.poids) { pSum += Number(c.poids); pN++; } if (c.valeur) { vSum += Number(c.valeur); vN++; } });
    res.json({ ok: true, reports: {
      caSource: { abonnements: Math.round(abos*100)/100, frais: Math.round(frais*100)/100, codes: Math.round(codes*100)/100 },
      topMerchants: merch, acquisition: acq, rechargesMoyen: rechMoyen,
      poidsMoyen: pN ? Math.round(pSum/pN*100)/100 : 0, valeurMoyenne: vN ? Math.round(vSum/vN*100)/100 : 0,
      colisCount: co.length,
    }});
  } catch (err) {
    console.error('reports error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Indicateurs (KPI) pour le pilotage : abonnés, colis, CA, répartitions.
app.get('/admin/stats', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: clients } = await db.from('clients').select('offre, ville, created_at, wallet_balance, last_seen');
    const { data: colis } = await db.from('colis').select('statut, valeur, poids, frais_envoi, created_at, received_at');
    const { data: recharges } = await db.from('recharges').select('montant, moyen, created_at');
    const rch = recharges || [];
    var visToday = 0, vis7 = 0;
    try {
      const today = new Date().toISOString().slice(0, 10);
      const d7 = new Date(Date.now() - 6 * 86400000).toISOString().slice(0, 10);
      const { data: vrows } = await db.from('visites').select('jour, count').gte('jour', d7);
      (vrows || []).forEach(function (v) { vis7 += Number(v.count || 0); if (v.jour === today) visToday = Number(v.count || 0); });
    } catch (e) {}
    const cl = clients || [], co = colis || [];
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const monthDay = now.getDate();
    const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
    const onlineCut = new Date(now.getTime() - 5 * 60000); // en ligne = vu il y a < 5 min
    const norm = function (s) { s = (s || '').toLowerCase(); return s.indexOf('mokili') >= 0 ? 'mokili' : s.indexOf('familia') >= 0 ? 'familia' : 'bokolo'; };
    const byOffre = { bokolo: 0, familia: 0, mokili: 0 };
    const byOffreToday = { bokolo: 0, familia: 0, mokili: 0 };
    const byVille = {};
    let clientsThisMonth = 0, clientsToday = 0, onlineNow = 0, clientsPrevMonth = 0, soldeTotal = 0;
    const prevMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    cl.forEach(function (c) {
      var o = norm(c.offre); byOffre[o]++;
      soldeTotal += Number(c.wallet_balance || 0);
      const v = (c.ville || 'Inconnue'); byVille[v] = (byVille[v] || 0) + 1;
      const dt = c.created_at ? new Date(c.created_at) : null;
      if (dt && dt >= monthStart) clientsThisMonth++;
      if (dt && dt >= prevMonthStart && dt < monthStart) clientsPrevMonth++;
      if (dt && dt >= dayStart) { clientsToday++; byOffreToday[o]++; }
      if (c.last_seen && new Date(c.last_seen) >= onlineCut) onlineNow++;
    });
    const byStatut = {};
    let valeurTotale = 0, poidsTotal = 0, fraisEnvoiTotal = 0, colisThisMonth = 0, colisToday = 0, fraisEnvoiToday = 0;
    // CA du jour (abonnements créés aujourd'hui + frais d'envoi du jour)
    const PRICES = { bokolo: 9.99, familia: 19.90, mokili: 49.90 };
    let caToday = fraisEnvoiToday;
    // Temps moyen de livraison (received_at → livre) — approximé via received_at des colis livrés
    let delaiSum = 0, delaiN = 0;
    co.forEach(function (c) {
      byStatut[c.statut || 'declare'] = (byStatut[c.statut || 'declare'] || 0) + 1;
      valeurTotale += Number(c.valeur || 0);
      poidsTotal += Number(c.poids || 0);
      fraisEnvoiTotal += Number(c.frais_envoi || 0);
      if (c.created_at && new Date(c.created_at) >= monthStart) colisThisMonth++;
      if (c.created_at && new Date(c.created_at) >= dayStart) { colisToday++; fraisEnvoiToday += Number(c.frais_envoi || 0); }
      if (c.statut === 'livre' && c.received_at && c.created_at) {
        const d = (new Date(c.received_at) - new Date(c.created_at)) / 86400000;
        if (d >= 0 && d < 120) { delaiSum += d; delaiN++; }
      }
    });
    caToday = fraisEnvoiToday + clientsToday >= 0 ? fraisEnvoiToday
      + byOffreToday.bokolo * PRICES.bokolo + byOffreToday.familia * PRICES.familia + byOffreToday.mokili * PRICES.mokili : 0;
    const mrr = byOffre.bokolo * PRICES.bokolo + byOffre.familia * PRICES.familia + byOffre.mokili * PRICES.mokili;
    const revParOffre = {
      bokolo: byOffre.bokolo * PRICES.bokolo,
      familia: byOffre.familia * PRICES.familia,
      mokili: byOffre.mokili * PRICES.mokili
    };
    // Conversion visiteurs → abonnés (si un compteur de visites existe, sinon null)
    const croissance = clientsPrevMonth > 0 ? Math.round((clientsThisMonth - clientsPrevMonth) / clientsPrevMonth * 100) : null;
    // Projection fin de mois (CA frais d'envoi du mois extrapolé)
    let fraisMois = 0; co.forEach(function (c) { if (c.created_at && new Date(c.created_at) >= monthStart) fraisMois += Number(c.frais_envoi || 0); });
    const projFinMois = monthDay > 0 ? Math.round((mrr + fraisMois) / monthDay * daysInMonth) : mrr;
    // Ventes par code Tiinda (recharges validées) — comptées comme du CA à leur date.
    let codeVentesToday = 0, codeVentesMois = 0;
    function codeAgg(since) { let t = 0; rch.forEach(function (r) { if (r.moyen === 'code' && r.created_at && new Date(r.created_at) >= since && Number(r.montant) > 0) t += Number(r.montant); }); return Math.round(t * 100) / 100; }
    codeVentesToday = codeAgg(dayStart);
    codeVentesMois = codeAgg(monthStart);
    const delaiMoyen = delaiN ? Math.round(delaiSum / delaiN * 10) / 10 : null;
    // Vues par période : semaine / mois / trimestre / année (nouveaux clients, colis, frais encaissés)
    const startOfWeek = new Date(now); const dow = (now.getDay() + 6) % 7; startOfWeek.setDate(now.getDate() - dow); startOfWeek.setHours(0,0,0,0);
    const qStart = new Date(now.getFullYear(), Math.floor(now.getMonth()/3)*3, 1);
    const yStart = new Date(now.getFullYear(), 0, 1);
    function periodAgg(since) {
      let nc = 0, np = 0, frais = 0, codes = 0; const off = { bokolo:0, familia:0, mokili:0 };
      cl.forEach(function (c) { if (c.created_at && new Date(c.created_at) >= since) { nc++; off[norm(c.offre)]++; } });
      co.forEach(function (c) { if (c.created_at && new Date(c.created_at) >= since) { np++; frais += Number(c.frais_envoi || 0); } });
      rch.forEach(function (r) { if (r.moyen === 'code' && r.created_at && new Date(r.created_at) >= since && Number(r.montant) > 0) codes += Number(r.montant); });
      const abo = off.bokolo*PRICES.bokolo + off.familia*PRICES.familia + off.mokili*PRICES.mokili;
      return { clients: nc, colis: np, frais: Math.round(frais*100)/100, codes: Math.round(codes*100)/100, ca: Math.round((abo+frais+codes)*100)/100 };
    }
    const periods = {
      semaine: periodAgg(startOfWeek),
      mois: periodAgg(monthStart),
      trimestre: periodAgg(qStart),
      annee: periodAgg(yStart)
    };
    res.json({ ok: true, stats: {
      clientsTotal: cl.length, clientsThisMonth: clientsThisMonth, clientsToday: clientsToday, onlineNow: onlineNow,
      clientsPrevMonth: clientsPrevMonth, croissance: croissance,
      colisTotal: co.length, colisThisMonth: colisThisMonth, colisToday: colisToday,
      byOffre: byOffre, byOffreToday: byOffreToday, byVille: byVille, byStatut: byStatut,
      valeurTotale: valeurTotale, poidsTotal: poidsTotal, fraisEnvoiTotal: fraisEnvoiTotal, fraisEnvoiToday: fraisEnvoiToday,
      caToday: caToday + codeVentesToday, mrr: mrr, revParOffre: revParOffre, projFinMois: projFinMois, delaiMoyen: delaiMoyen,
      codeVentesToday: codeVentesToday, codeVentesMois: codeVentesMois,
      soldeTotal: Math.round(soldeTotal * 100) / 100,
      visitorsToday: visToday, visitors7: vis7,
      periods: periods,
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
    // Marque le code SEULEMENT s'il est encore libre : deux clics simultanés
    // ne peuvent plus le consommer deux fois.
    const { data: pris } = await db.from('recharge_codes')
      .update({ used: true, used_by: cli.id, used_at: new Date().toISOString() })
      .eq('id', rc.id).eq('used', false)
      .select('id');
    if (!pris || !pris.length) return res.json({ ok: false, error: 'code_deja_utilise' });
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

// ── POINTS RELAIS ────────────────────────────────────────────────────────
// (PUBLIC) Liste des points relais actifs (affichés côté client).
app.get('/points-relais', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data } = await db.from('points_relais').select('*').eq('actif', true).order('created_at', { ascending: true });
    res.json({ ok: true, points: data || [] });
  } catch (e) { console.error('points get error:', e.message); res.json({ ok: false }); }
});
// (ADMIN) Liste complète.
app.get('/admin/points-relais', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data } = await db.from('points_relais').select('*').order('created_at', { ascending: true });
    res.json({ ok: true, points: data || [] });
  } catch (e) { res.status(500).json({ ok: false }); }
});
// (ADMIN) Créer / modifier.
app.post('/admin/points-relais/save', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const b = req.body || {};
    const row = { nom: b.nom || null, adresse: b.adresse || null, ville: b.ville || null, telephone: b.telephone || null, horaires: b.horaires || null, actif: b.actif !== false };
    let data, error;
    if (b.id) { ({ data, error } = await db.from('points_relais').update(row).eq('id', b.id).select().single()); }
    else { ({ data, error } = await db.from('points_relais').insert(row).select().single()); }
    if (error) { console.error('points save error:', error.message); return res.json({ ok: false }); }
    res.json({ ok: true, point: data });
  } catch (e) { res.status(500).json({ ok: false }); }
});
// (ADMIN) Supprimer.
app.post('/admin/points-relais/delete', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    if (!req.body.id) return res.json({ ok: false });
    await db.from('points_relais').delete().eq('id', req.body.id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false }); }
});

// (ADMIN) Supervision du parrainage : qui a parrainé qui + récompenses versées.
app.get('/admin/referrals', requireAdmin, async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const { data: clients } = await db.from('clients').select('id, tiinda_id, prenom, nom, phone, parrain_id, created_at');
    const { data: recs } = await db.from('recharges').select('client_id, montant').eq('moyen', 'parrainage');
    const cl = clients || [];
    const byId = {}; cl.forEach(function (c) { byId[c.id] = c; });
    const gains = {}; (recs || []).forEach(function (r) { gains[r.client_id] = (gains[r.client_id] || 0) + Number(r.montant || 0); });
    // Compte les filleuls par parrain.
    const filleulsCount = {};
    cl.forEach(function (c) { if (c.parrain_id) filleulsCount[c.parrain_id] = (filleulsCount[c.parrain_id] || 0) + 1; });
    // Parrains (clients ayant au moins 1 filleul) + liste des filleuls.
    const parrains = cl.filter(function (c) { return filleulsCount[c.id]; }).map(function (p) {
      const fil = cl.filter(function (c) { return c.parrain_id === p.id; }).map(function (c) {
        return { nom: ((c.prenom || '') + ' ' + (c.nom || '')).trim(), tiinda_id: c.tiinda_id, date: c.created_at };
      });
      return {
        nom: ((p.prenom || '') + ' ' + (p.nom || '')).trim(), tiinda_id: p.tiinda_id, phone: p.phone,
        filleuls: fil.length, gains: Number(gains[p.id] || 0), liste: fil,
      };
    }).sort(function (a, b) { return b.filleuls - a.filleuls; });
    const totalGains = Object.keys(gains).reduce(function (s, k) { return s + gains[k]; }, 0);
    res.json({ ok: true, parrains: parrains, totalParrains: parrains.length, totalFilleuls: cl.filter(function (c) { return c.parrain_id; }).length, totalGains: totalGains });
  } catch (err) {
    console.error('admin referrals error:', err.message);
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

/* ── Rappels d'échéance d'abonnement ───────────────────────────────────────
   Appelé une fois par jour par le Cron Render. Protégé par CRON_SECRET.
   ───────────────────────────────────────────────────────────────────────── */
app.post('/cron/rappels', async (req, res) => {
  try {
    const secret = req.get('X-Cron-Secret') || '';
    if (!process.env.CRON_SECRET || secret !== process.env.CRON_SECRET) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    if (!db) return res.json({ ok: false, error: 'no_db' });

    const { data: liste, error } = await db.rpc('abonnements_a_rappeler');
    if (error) { console.error('rappels rpc:', error.message);
      return res.json({ ok: false, error: 'rpc_failed' }); }

    let envoyes = 0;
    for (const c of (liste || [])) {
      const fin = new Date(c.abonnement_fin);
      const finFr = fin.toLocaleDateString('fr-FR');
      const manque = Math.round((Number(c.prix_requis) - Number(c.wallet_balance)) * 100) / 100;
      const ref = 'RAPPEL-' + c.client_id + '-' + c.type_rappel + '-'
                + fin.toISOString().slice(0, 10);

      // Verrou d'unicité : si déjà envoyé, on passe.
      const { error: errRef } = await db.from('rappels_envoyes')
        .insert({ client_id: c.client_id, type: c.type_rappel, reference: ref });
      if (errRef) continue;

      const titre = c.type_rappel === 'J7'
        ? 'Votre forfait ' + c.offre + ' se renouvelle le ' + finFr
        : 'Dernier jour : rechargez pour garder votre forfait ' + c.offre;

      const corps = 'Solde actuel : ' + Number(c.wallet_balance).toFixed(2) + ' EUR. '
        + 'Il vous manque ' + manque.toFixed(2) + ' EUR pour le renouvellement du '
        + finFr + '. Sans recharge, votre compte repassera en offre Découverte.';

      if (c.notif_email && c.email && RESEND_API_KEY) {
        const html = '<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto">'
          + '<div style="background:#0057FF;color:#fff;padding:18px;border-radius:12px 12px 0 0;text-align:center">'
          + '<strong style="font-size:18px">TIINDA</strong></div>'
          + '<div style="border:1px solid #eee;border-top:none;padding:22px;border-radius:0 0 12px 12px">'
          + '<p>Bonjour ' + (c.prenom || '') + ',</p>'
          + '<p><strong>' + titre + '</strong></p>'
          + '<p>' + corps + '</p>'
          + '<p style="margin:24px 0"><a href="https://tiinda.com/pages/mon-espace" '
          + 'style="background:#0057FF;color:#fff;padding:12px 22px;border-radius:9px;'
          + 'text-decoration:none;font-weight:600">Recharger mon compte</a></p>'
          + '<p style="font-size:12.5px;color:#666">Vos colis et votre adresse restent actifs.</p>'
          + '</div></div>';
        try {
          await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({ from: MAIL_FROM || 'Tiinda <onboarding@resend.dev>',
              to: c.email, subject: 'Tiinda — ' + titre, html })
          });
        } catch (e) { console.error('rappel mail:', e.message); }
      }

      // WhatsApp : nécessite un template dédié approuvé par Meta
      // (3 variables : prénom, forfait, date). Renseignez TWILIO_WA_ABO_SID.
      if (c.notif_whatsapp && process.env.TWILIO_WHATSAPP_FROM && process.env.TWILIO_WA_ABO_SID) {
        try {
          await client.messages.create({
            from: 'whatsapp:' + process.env.TWILIO_WHATSAPP_FROM,
            to: 'whatsapp:' + c.phone,
            contentSid: process.env.TWILIO_WA_ABO_SID,
            contentVariables: JSON.stringify({
              '1': c.prenom || 'cher client', '2': c.offre, '3': finFr
            }),
          });
        } catch (e) { console.error('rappel wa:', e.message); }
      }

      envoyes++;
    }

    res.json({ ok: true, candidats: (liste || []).length, envoyes: envoyes });
  } catch (err) {
    console.error('cron rappels error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.listen(PORT, () => {
  console.log(`TIINDA backend en écoute sur le port ${PORT} — Supabase: ${db ? 'OK' : 'NON configuré'}`);
});
