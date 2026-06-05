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
  PORT = 3000,
} = process.env;

const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

// Connexion Supabase (uniquement si les clés sont présentes — évite un crash).
const db = (SUPABASE_URL && SUPABASE_SERVICE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
  : null;

const app = express();
app.use(express.json());

/* ── 0) CORS — autorise le thème Shopify à appeler ce backend directement ── */
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

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
  const { data: created, error } = await db.from('clients').insert({
    tiinda_id,
    prenom: info.prenom || null,
    nom:    info.nom || null,
    email:  info.email || null,
    phone,
    ville:  info.ville || null,
    offre:  info.offre || null,
  }).select().single();
  if (error) { console.error('create client error:', error.message); return null; }
  return created;
}

/* ── 4) Route : envoi du code (WhatsApp ou SMS selon OTP_CHANNEL) ────────── */
app.post('/send', verifyShopifyProxy, async (req, res) => {
  try {
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
    });

    res.json({
      ok: true,
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

/* ── 6) Route : récupérer un client par téléphone (pour la connexion) ────── */
app.get('/client', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const phone = toE164(req.query.phone);
    const { data } = await db.from('clients').select('*').eq('phone', phone).limit(1).maybeSingle();
    if (!data) return res.json({ ok: false, error: 'not_found' });
    res.json({ ok: true, client: {
      tiinda_id: data.tiinda_id, prenom: data.prenom, nom: data.nom,
      email: data.email, phone: data.phone, ville: data.ville,
      offre: data.offre, wallet_balance: data.wallet_balance,
    }});
  } catch (err) {
    console.error('client error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ── 7) Route : déclarer un colis ─────────────────────────────────────────
   Génère un numéro de suivi interne unique (TND + horodatage). */
app.post('/colis/declare', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const phone = toE164(req.body.phone);
    const { data: cli } = await db.from('clients').select('id').eq('phone', phone).limit(1).maybeSingle();
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
    res.json({ ok: true, colis: data });
  } catch (err) {
    console.error('declare error:', err.message);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ── 8) Route : lister les colis d'un client ──────────────────────────────── */
app.get('/colis', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const phone = toE164(req.query.phone);
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

app.get('/health', (_req, res) => res.json({ ok: true, db: !!db }));

app.listen(PORT, () => {
  console.log(`TIINDA backend en écoute sur le port ${PORT} — Supabase: ${db ? 'OK' : 'NON configuré'}`);
});
