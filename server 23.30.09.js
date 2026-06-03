/* ─────────────────────────────────────────────────────────────────────────
   TIINDA — Backend OTP WhatsApp (Twilio Verify + Shopify App Proxy)
   ─────────────────────────────────────────────────────────────────────────
   Rôle : faire l'intermédiaire entre le thème Shopify et Twilio Verify.
   Le navigateur appelle  https://tiinda.com/apps/otp/send|verify
   → Shopify (App Proxy) relaie vers CE serveur
   → ce serveur parle à Twilio (avec l'Auth Token, qui reste secret ici).

   Deux routes :
     POST /send    { phone }           → envoie un code WhatsApp
     POST /verify  { phone, code }     → vérifie le code  → { ok: true|false }

   ⚠️  Ne mets JAMAIS SID / AUTH_TOKEN dans le thème Shopify ou le JS front.
       Ils vivent uniquement dans les variables d'environnement de ce serveur.
   ───────────────────────────────────────────────────────────────────────── */

const express = require('express');
const crypto  = require('crypto');
const twilio  = require('twilio');

const {
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_VERIFY_SERVICE_SID,   // SID du Verify Service (commence par "VA...")
  SHOPIFY_API_SECRET,          // "API secret key" de ton app Shopify (pour signer le proxy)
  PORT = 3000,
} = process.env;

const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

const app = express();
app.use(express.json());

/* ─────────────────────────────────────────────────────────────────────────
   0) CORS — autorise le thème Shopify à appeler ce backend directement
   ─────────────────────────────────────────────────────────────────────────
   Quand on n'utilise PAS l'App Proxy Shopify, le navigateur appelle ce
   serveur en "cross-origin" (depuis tiinda.com vers onrender.com). Sans ces
   en-têtes, le navigateur bloque la requête. On répond aussi au "preflight"
   OPTIONS que le navigateur envoie avant un POST JSON.
   ───────────────────────────────────────────────────────────────────────── */
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

/* ─────────────────────────────────────────────────────────────────────────
   1) Vérification de la signature Shopify App Proxy
   ─────────────────────────────────────────────────────────────────────────
   Shopify ajoute un paramètre ?signature=... à chaque requête proxifiée.
   On recalcule le HMAC avec l'API secret pour s'assurer que la requête
   vient bien de Shopify (et pas d'un tiers qui appelle ton backend en direct).
   Doc : https://shopify.dev/docs/apps/online-store/app-proxies
   ───────────────────────────────────────────────────────────────────────── */
function verifyShopifyProxy(req, res, next) {
  // En dev local sans App Proxy, tu peux court-circuiter avec SKIP_PROXY_CHECK=1
  if (process.env.SKIP_PROXY_CHECK === '1') return next();

  const { signature, ...params } = req.query;
  if (!signature) return res.status(401).json({ ok: false, error: 'missing signature' });

  // Concatène les paramètres triés : "key=value" (sans séparateur), ordre alphabétique
  const message = Object.keys(params)
    .sort()
    .map((key) => {
      const value = Array.isArray(params[key]) ? params[key].join(',') : params[key];
      return `${key}=${value}`;
    })
    .join('');

  const digest = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(message)
    .digest('hex');

  // Comparaison à temps constant
  const ok =
    digest.length === String(signature).length &&
    crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(String(signature)));

  if (!ok) return res.status(401).json({ ok: false, error: 'invalid signature' });
  next();
}

/* ─────────────────────────────────────────────────────────────────────────
   2) Normalisation du numéro au format E.164 attendu par Twilio
      ex : "+243 81 234 56 78"  →  "+24381234 5678"  →  "+243812345678"
   ───────────────────────────────────────────────────────────────────────── */
function toE164(phone) {
  if (!phone) return '';
  const trimmed = String(phone).trim();
  const plus = trimmed.startsWith('+') ? '+' : '+';
  const digits = trimmed.replace(/\D/g, '');
  return plus + digits;
}

/* ─────────────────────────────────────────────────────────────────────────
   3) Route : envoi du code par WhatsApp
   ───────────────────────────────────────────────────────────────────────── */
app.post('/send', verifyShopifyProxy, async (req, res) => {
  try {
    const phone = toE164(req.body.phone);
    if (!phone || phone.length < 8) {
      return res.status(400).json({ ok: false, error: 'invalid phone' });
    }

    await client.verify.v2
      .services(TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({ to: phone, channel: 'whatsapp' });

    // On ne renvoie jamais le code — Twilio le garde côté serveur.
    res.json({ ok: true });
  } catch (err) {
    console.error('send error:', err.message);
    res.status(500).json({ ok: false, error: 'send_failed' });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   4) Route : vérification du code saisi par le client
   ───────────────────────────────────────────────────────────────────────── */
app.post('/verify', verifyShopifyProxy, async (req, res) => {
  try {
    const phone = toE164(req.body.phone);
    const code = String(req.body.code || '').replace(/\D/g, '');
    if (!phone || code.length !== 6) {
      return res.status(400).json({ ok: false, error: 'invalid_input' });
    }

    const check = await client.verify.v2
      .services(TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({ to: phone, code });

    const approved = check.status === 'approved';

    // ✅ Si approuvé : c'est ICI que tu crées / valides le client Shopify
    //    (Admin API : créer le customer, marquer le téléphone vérifié,
    //     générer l'identifiant TIINDA000xxx, etc.)
    // if (approved) { await createShopifyCustomer(phone, req.body); }

    res.json({ ok: approved });
  } catch (err) {
    // Twilio renvoie une erreur si le code a expiré ou trop de tentatives
    console.error('verify error:', err.message);
    res.status(200).json({ ok: false, error: 'verify_failed' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`TIINDA OTP backend en écoute sur le port ${PORT}`);
});
