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
app.post('/colis/declare', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const phone = toE164(req.body.phone);
    const { data: cli } = await db.from('clients').select('id, email, prenom, tiinda_id').eq('phone', phone).limit(1).maybeSingle();
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
app.get('/track', async (req, res) => {
  try {
    if (!db) return res.json({ ok: false, error: 'no_db' });
    const q = String(req.query.q || '').trim().replace(/[^A-Za-z0-9\-]/g, '');
    if (!q) return res.json({ ok: false, error: 'missing_query' });
    // Retrouve le colis par n° interne Tiinda (TND…) OU n° transporteur.
    // → taper le numéro Tiinda suffit : il est relié au n° transporteur déclaré.
    let { data: colis } = await db.from('colis').select('*')
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

app.get('/health', (_req, res) => res.json({ ok: true, db: !!db, track123: !!TRACK123_API_KEY }));

app.listen(PORT, () => {
  console.log(`TIINDA backend en écoute sur le port ${PORT} — Supabase: ${db ? 'OK' : 'NON configuré'}`);
});
