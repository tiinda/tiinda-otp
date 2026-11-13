/* ─────────────────────────────────────────────────────────────────────────
   TIINDA, Espace opérateur de l'agence de Brazzaville
   ─────────────────────────────────────────────────────────────────────────
   Branché depuis server.js par :  require('./operateur')(app, outils)

   Comptes agents
     - James crée le compte (identifiant + nom) : le serveur donne un code
       d'activation à usage unique, valable 48 h.
     - Première connexion : l'agent tape ce code, choisit SON mot de passe et
       relie Google Authenticator (QR code).
     - Ensuite, à chaque connexion : mot de passe, puis code à 6 chiffres.

   Routes agent (en-tête x-op-session)
     POST /op/login, /op/code, /op/activation/debut, /op/activation/fin
     GET  /op/moi, /op/jour, /op/colis, /op/boutique, /op/client, /op/caisse, /op/borne
     POST /op/remise, /op/reception, /op/recharge, /op/borne/depot,
          /op/borne/rendre, /op/cloture

   Routes James (session admin)
     GET  /admin/operateurs, /admin/recharges-op
     POST /admin/operateurs, /admin/operateurs/reset, /admin/operateurs/actif,
          /admin/recharges-op/envoyer, /admin/recharges-op/refuser

   Ne touche à aucune route Tiinda existante : seules des routes /op/* et
   /admin/operateurs*, /admin/recharges-op* sont ajoutées. Les colis passent
   par les mêmes statuts que le scan PDA (arrive → disponible → livre).
   ───────────────────────────────────────────────────────────────────────── */

const crypto = require('crypto');

const TAUX_FCFA = 655.957;            // 1 € = 655,957 FCFA (parité fixe)
const PRIX_BORNE_FCFA = 150;          // recharge de téléphone à la borne
const NB_PLACES_BORNE = 50;
const OP_SESSION_MS = 12 * 3600000;   // session agent : 12 h
const ACTIVATION_MS = 48 * 3600000;   // code d'activation : 48 h

module.exports = function brancherOperateur(app, o) {
  const { db, twilio, rateLimit, clientIp, b64url, SESSION_KEY, base32Decode, totpCode,
          requireAdmin, notifyColisStatus, noterEtapeTiinda, hashPassword, verifyPassword } = o;

  /* ── Outils ──────────────────────────────────────────────────────────── */
  const now = () => new Date().toISOString();
  const rond2 = (n) => Math.round(Number(n || 0) * 100) / 100;
  const fcfaVersEur = (f) => rond2(Number(f || 0) / TAUX_FCFA);
  /* Recharges proposées à l'agence : 10, 20 et 50 € (sans bonus : le bonus est réservé aux achats en ligne).
     Prix en FCFA = parité fixe 655,957, arrondi au 50 FCFA supérieur : Colispo ne perd jamais sur la conversion. */
  const PACKS = [10, 20, 50].map((eur) => ({ eur, fcfa: Math.ceil((eur * TAUX_FCFA) / 50) * 50 }));
  /* Crédit donné au client : la valeur du pack, ou pour un montant libre la conversion arrondie au centime inférieur. */
  const creditPourFcfa = (f) => { const p = PACKS.find((x) => x.fcfa === f); return p ? p.eur : Math.floor((Number(f || 0) / TAUX_FCFA) * 100) / 100; };
  const MOYENS = { especes: 'Espèces', mtn: 'MTN Mobile Money', airtel: 'Airtel Money' };

  function signer(prefixe, obj, dureeMs) {
    const payload = b64url(JSON.stringify(Object.assign({}, obj, { exp: Date.now() + dureeMs })));
    const sig = b64url(crypto.createHmac('sha256', SESSION_KEY).update(prefixe + ':' + payload).digest());
    return payload + '.' + sig;
  }
  function lire(prefixe, jeton) {
    if (!jeton || typeof jeton !== 'string' || jeton.indexOf('.') < 0) return null;
    const [payload, sig] = jeton.split('.');
    const attendu = b64url(crypto.createHmac('sha256', SESSION_KEY).update(prefixe + ':' + payload).digest());
    if (!sig || sig.length !== attendu.length) return null;
    try { if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(attendu))) return null; } catch (e) { return null; }
    let d; try { d = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); } catch (e) { return null; }
    if (!d || !d.exp || Date.now() > d.exp) return null;
    return d;
  }

  function base32Encode(buf) {
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, val = 0, out = '';
    for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; } }
    if (bits > 0) out += A[(val << (5 - bits)) & 31];
    return out;
  }
  // Vérifie un code Google Authenticator ; renvoie le compteur utilisé (anti-rejeu) ou -1.
  function compteurTotp(secret, code, dernier) {
    const c = String(code || '').replace(/\D/g, '');
    if (c.length !== 6 || !secret) return -1;
    const key = base32Decode(secret);
    const t = Math.floor(Date.now() / 30000);
    for (let d = -1; d <= 1; d++) {
      const ctr = t + d;
      if (ctr <= Number(dernier || 0)) continue;
      const a = Buffer.from(totpCode(key, ctr)), b = Buffer.from(c);
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) return ctr;
    }
    return -1;
  }
  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
  function aleatoire(n, alphabet) {
    const A = alphabet || 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = crypto.randomBytes(n); let s = '';
    for (let i = 0; i < n; i++) s += A[bytes[i] % A.length];
    return s;
  }
  /* Numéro de téléphone au format international. Un numéro congolais tapé
     « 06 586 84 41 » devient +242065868441. */
  function normTel(brut) {
    let s = String(brut || '').trim();
    const plus = s.startsWith('+');
    s = s.replace(/\D/g, '');
    if (!s) return '';
    if (plus) return '+' + s;
    if (s.startsWith('00')) return '+' + s.slice(2);
    if (s.startsWith('242') && s.length >= 12) return '+' + s;
    if (s.startsWith('0') && s.length === 9) return '+242' + s;
    if (s.length === 9 && (s.startsWith('6') || s.startsWith('5') || s.startsWith('4') || s.startsWith('2'))) return '+2420' + s;
    return '+' + s;
  }
  const masquerTel = (t) => { const s = String(t || ''); return s.length > 6 ? s.slice(0, 6) + ' •• •• ' + s.slice(-2) : s; };
  const normCode = (c) => String(c || '').trim().toUpperCase().replace(/[^A-Z0-9\-]/g, '');
  const jourParis = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Brazzaville', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
  // Minuit à Brazzaville (UTC+1, sans changement d'heure).
  function debutJourBzv() {
    const [y, m, d] = jourParis().split('-').map(Number);
    return new Date(Date.UTC(y, m - 1, d) - 3600000).toISOString();
  }
  async function journal(op, type, ref, detail) {
    try { await db.from('op_journal').insert({ operateur_id: op.id, type, ref, detail: detail || null }); }
    catch (e) { /* le journal ne doit jamais bloquer une opération */ }
  }
  const pasDeBase = (res) => res.json({ ok: false, error: 'no_db' });
  const erreurServeur = (res, quoi, err) => { console.error('op ' + quoi + ':', err && err.message); res.status(500).json({ ok: false, error: 'server_error' }); };

  /* ── Session agent ───────────────────────────────────────────────────── */
  async function requireOp(req, res, next) {
    const d = lire('op', req.headers['x-op-session']);
    if (!d || !d.id || !db) return res.status(401).json({ ok: false, error: 'unauthorized' });
    const { data: op } = await db.from('operateurs').select('id, identifiant, nom, actif, agence').eq('id', d.id).maybeSingle();
    if (!op || !op.actif) return res.status(401).json({ ok: false, error: 'unauthorized' });
    req.op = op; next();
  }
  const ouvrirSession = (op) => ({ ok: true, session: signer('op', { id: op.id }, OP_SESSION_MS), operateur: { identifiant: op.identifiant, nom: op.nom, agence: op.agence } });

  /* Étape 1 : identifiant + mot de passe → jeton de 5 min pour l'étape du code. */
  app.post('/op/login', async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      const ip = clientIp(req);
      if (!rateLimit('op-login:' + ip, 8, 15 * 60000)) return res.status(429).json({ ok: false, error: 'trop_de_tentatives' });
      const ident = String((req.body || {}).identifiant || '').trim().toLowerCase();
      const { data: op } = await db.from('operateurs').select('*').eq('identifiant', ident).maybeSingle();
      if (!op || !op.actif || !op.mdp_hash || !verifyPassword((req.body || {}).mot_de_passe, op.mdp_hash)) {
        console.warn('op login refusé', ident, ip);
        return res.status(401).json({ ok: false, error: 'identifiants' });
      }
      res.json({ ok: true, etape: 'code', jeton: signer('op1', { id: op.id }, 5 * 60000) });
    } catch (err) { erreurServeur(res, 'login', err); }
  });

  /* Étape 2 : code Google Authenticator → session de 12 h. */
  app.post('/op/code', async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      if (!rateLimit('op-code:' + clientIp(req), 8, 15 * 60000)) return res.status(429).json({ ok: false, error: 'trop_de_tentatives' });
      const d = lire('op1', (req.body || {}).jeton);
      if (!d) return res.status(401).json({ ok: false, error: 'jeton_expire' });
      const { data: op } = await db.from('operateurs').select('*').eq('id', d.id).maybeSingle();
      if (!op || !op.actif) return res.status(401).json({ ok: false, error: 'identifiants' });
      const ctr = compteurTotp(op.totp_secret, (req.body || {}).code, op.dernier_compteur);
      if (ctr < 0) return res.status(401).json({ ok: false, error: 'code_invalide' });
      await db.from('operateurs').update({ dernier_compteur: ctr, derniere_connexion: now() }).eq('id', op.id);
      await journal(op, 'connexion', null, { ip: clientIp(req) });
      res.json(ouvrirSession(op));
    } catch (err) { erreurServeur(res, 'code', err); }
  });

  /* Première connexion, étape 1 : identifiant + code d'activation donné par James.
     Renvoie la clé Google Authenticator à scanner. */
  app.post('/op/activation/debut', async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      if (!rateLimit('op-act:' + clientIp(req), 6, 15 * 60000)) return res.status(429).json({ ok: false, error: 'trop_de_tentatives' });
      const b = req.body || {};
      const ident = String(b.identifiant || '').trim().toLowerCase();
      const { data: op } = await db.from('operateurs').select('*').eq('identifiant', ident).maybeSingle();
      const codeOk = op && op.activation_hash && op.activation_hash === sha(normCode(b.code_activation))
        && op.activation_expire && Date.now() < new Date(op.activation_expire).getTime();
      if (!codeOk) return res.status(401).json({ ok: false, error: 'code_activation_invalide' });
      const secret = base32Encode(crypto.randomBytes(20));
      await db.from('operateurs').update({ totp_secret_tmp: secret }).eq('id', op.id);
      const label = encodeURIComponent('Colispo:' + op.identifiant);
      res.json({
        ok: true,
        jeton: signer('opact', { id: op.id }, 20 * 60000),
        secret: secret,
        otpauth: 'otpauth://totp/' + label + '?secret=' + secret + '&issuer=Colispo&digits=6&period=30',
        nom: op.nom,
      });
    } catch (err) { erreurServeur(res, 'activation debut', err); }
  });

  /* Première connexion, étape 2 : mot de passe choisi + premier code de l'application. */
  app.post('/op/activation/fin', async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      const b = req.body || {};
      const d = lire('opact', b.jeton);
      if (!d) return res.status(401).json({ ok: false, error: 'jeton_expire' });
      const mdp = String(b.mot_de_passe || '');
      if (mdp.length < 10 || !/[A-Z]/.test(mdp) || !/\d/.test(mdp)) return res.json({ ok: false, error: 'mot_de_passe_faible' });
      const { data: op } = await db.from('operateurs').select('*').eq('id', d.id).maybeSingle();
      if (!op || !op.totp_secret_tmp || !op.activation_hash) return res.status(401).json({ ok: false, error: 'activation_impossible' });
      const ctr = compteurTotp(op.totp_secret_tmp, b.code, 0);
      if (ctr < 0) return res.json({ ok: false, error: 'code_invalide' });
      const { error } = await db.from('operateurs').update({
        mdp_hash: hashPassword(mdp), totp_secret: op.totp_secret_tmp, totp_secret_tmp: null,
        activation_hash: null, activation_expire: null, active_le: now(), actif: true,
        dernier_compteur: ctr, derniere_connexion: now(),
      }).eq('id', op.id);
      if (error) return res.json({ ok: false, error: 'enregistrement_impossible' });
      await journal(op, 'activation', null, null);
      res.json(ouvrirSession(op));
    } catch (err) { erreurServeur(res, 'activation fin', err); }
  });

  app.get('/op/moi', requireOp, (req, res) => res.json({ ok: true, operateur: { identifiant: req.op.identifiant, nom: req.op.nom, agence: req.op.agence } }));

  /* ── Colis ───────────────────────────────────────────────────────────── */
  const SELECT_COLIS = 'id, tracking_interne, tracking_externe, statut, poids, description, client_id, disponible_at, arrive_at, case_congo, clients(prenom,nom,phone,offre)';
  function ficheColis(c) {
    const cl = c.clients || {};
    const depuis = c.disponible_at ? Math.floor((Date.now() - new Date(c.disponible_at).getTime()) / 86400000) : null;
    return {
      id: c.id, tnd: c.tracking_interne, statut: c.statut, poids: c.poids, description: c.description,
      case_congo: c.case_congo || null, disponible_at: c.disponible_at, jours: depuis,
      client: { nom: [cl.prenom, cl.nom ? String(cl.nom).charAt(0) + '.' : ''].filter(Boolean).join(' '), tel: cl.phone || '', tel_masque: masquerTel(cl.phone), forfait: cl.offre || '' },
    };
  }
  async function trouverColis(code) {
    const c = normCode(code);
    if (!c || c.startsWith('CLB')) return null; // Coolibo : pas dans cet écran
    let r = await db.from('colis').select(SELECT_COLIS).or('tracking_interne.eq.' + c + ',tracking_externe.eq.' + c).limit(1).maybeSingle();
    if (r.error && /case_congo/.test(r.error.message || '')) {
      r = await db.from('colis').select(SELECT_COLIS.replace(', case_congo', '')).or('tracking_interne.eq.' + c + ',tracking_externe.eq.' + c).limit(1).maybeSingle();
    }
    return r.data || null;
  }

  /* Recherche au comptoir : un numéro TND, ou le téléphone du client (ses colis disponibles). */
  app.get('/op/colis', requireOp, async (req, res) => {
    try {
      const q = String(req.query.q || '').trim();
      if (!q) return res.json({ ok: false, error: 'missing' });
      if (/^[A-Za-z]/.test(q)) {
        const c = await trouverColis(q);
        if (!c) return res.json({ ok: false, error: 'colis_introuvable' });
        return res.json({ ok: true, colis: [ficheColis(c)] });
      }
      const tel = normTel(q);
      const { data: cli } = await db.from('clients').select('id').eq('phone', tel).maybeSingle();
      if (!cli) return res.json({ ok: false, error: 'client_introuvable' });
      const { data } = await db.from('colis').select(SELECT_COLIS).eq('client_id', cli.id).in('statut', ['arrive', 'disponible']).order('disponible_at', { ascending: true });
      if (!data || !data.length) return res.json({ ok: false, error: 'aucun_colis' });
      res.json({ ok: true, colis: data.map(ficheColis) });
    } catch (err) { erreurServeur(res, 'colis', err); }
  });

  /* Remise au client : pièce d'identité vérifiée obligatoire. */
  app.post('/op/remise', requireOp, async (req, res) => {
    try {
      const b = req.body || {};
      if (!b.piece_verifiee || !b.nom_verifie) return res.json({ ok: false, error: 'verifications_requises' });
      const c = await trouverColis(b.tnd);
      if (!c) return res.json({ ok: false, error: 'colis_introuvable' });
      if (c.statut === 'livre') return res.json({ ok: false, error: 'deja_remis' });
      if (c.statut !== 'disponible') return res.json({ ok: false, error: 'pas_disponible', statut_actuel: c.statut });
      const { data, error } = await db.from('colis').update({ statut: 'livre' }).eq('id', c.id).eq('statut', 'disponible').select().maybeSingle();
      if (error || !data) return res.json({ ok: false, error: 'update_failed' });
      await db.from('colis').update({ case_congo: null }).eq('id', c.id).then(() => {}, () => {});
      await noterEtapeTiinda(c.id, 'livre');
      if (c.client_id) notifyColisStatus(c.client_id, data).catch(() => {});
      await journal(req.op, 'remise', c.tracking_interne, { piece: String(b.piece || '').slice(0, 30), case: c.case_congo || null });
      res.json({ ok: true, colis: ficheColis(Object.assign({}, c, { statut: 'livre' })) });
    } catch (err) { erreurServeur(res, 'remise', err); }
  });

  /* Réception d'un vol : scan du colis puis de la case où il est rangé → disponible. */
  /* Emplacements de l'agence de Brazzaville : étagères A à D, 25 cases chacune (A01 … D25).
     Pour agrandir sans toucher au code : variables Render OP_ETAGERES (ex. A,B,C,D,E) et OP_CASES (ex. 30). */
  const ETAGERES = String(process.env.OP_ETAGERES || 'A,B,C,D').split(',').map((x) => x.trim().toUpperCase()).filter(Boolean);
  const CASES_PAR_ETAGERE = Math.max(1, parseInt(process.env.OP_CASES || '25', 10) || 25);
  const EMPLACEMENTS = [];
  ETAGERES.forEach((e) => { for (let i = 1; i <= CASES_PAR_ETAGERE; i++) EMPLACEMENTS.push(e + String(i).padStart(2, '0')); });
  async function choisirEmplacement(colis) {
    const { data } = await db.from('colis').select('client_id, case_congo').eq('statut', 'disponible').limit(5000);
    const occupes = (data || []).filter((x) => x.case_congo);
    if (colis.client_id) {
      const meme = occupes.find((x) => x.client_id === colis.client_id);
      if (meme) return { case: meme.case_congo, meme_client: true };
    }
    const prises = new Set(occupes.map((x) => x.case_congo));
    const libre = EMPLACEMENTS.find((x) => !prises.has(x));
    return libre ? { case: libre, meme_client: false } : null;
  }

  /* Réception d'un vol, en deux temps avec double contrôle :
     1) /op/reception/proposer : on scanne le colis, le système donne l'emplacement (rien n'est enregistré) ;
     2) /op/reception : on scanne l'étiquette de l'emplacement ; si c'est le bon, le colis passe « disponible » et le client est prévenu. */
  async function verifierColisReception(tnd) {
    const c = await trouverColis(tnd);
    if (!c) return { erreur: { ok: false, error: 'colis_introuvable' } };
    if (['disponible', 'livre'].includes(c.statut)) return { erreur: { ok: false, error: 'deja_scanne', statut_actuel: c.statut, case_congo: c.case_congo || null } };
    if (!['expedie', 'arrive'].includes(c.statut)) return { erreur: { ok: false, error: 'pas_encore_expedie', statut_actuel: c.statut } };
    return { colis: c };
  }
  const normCase = (v) => String(v || '').trim().toUpperCase().replace(/^EMP[-\s]?/, '').replace(/[^A-Z0-9]/g, '').slice(0, 12);

  app.get('/op/packs', requireOp, (req, res) => res.json({ ok: true, taux: TAUX_FCFA, packs: PACKS, moyens: MOYENS }));
  app.get('/op/emplacements', requireOp, (req, res) => res.json({ ok: true, etageres: ETAGERES, cases_par_etagere: CASES_PAR_ETAGERE, emplacements: EMPLACEMENTS }));

  app.post('/op/reception/proposer', requireOp, async (req, res) => {
    try {
      const v = await verifierColisReception((req.body || {}).tnd);
      if (v.erreur) return res.json(v.erreur);
      const choix = await choisirEmplacement(v.colis);
      if (!choix) return res.json({ ok: false, error: 'boutique_pleine' });
      res.json({ ok: true, case: choix.case, meme_client: choix.meme_client, colis: ficheColis(Object.assign({}, v.colis, { case_congo: choix.case })) });
    } catch (err) { erreurServeur(res, 'reception proposer', err); }
  });

  app.post('/op/reception', requireOp, async (req, res) => {
    try {
      const b = req.body || {};
      const scannee = normCase(b.case);
      if (!scannee) return res.json({ ok: false, error: 'scan_emplacement_requis' });
      const v = await verifierColisReception(b.tnd);
      if (v.erreur) return res.json(v.erreur);
      const c = v.colis;
      const choix = await choisirEmplacement(c);
      if (!choix) return res.json({ ok: false, error: 'boutique_pleine' });
      if (scannee !== choix.case) {
        await journal(req.op, 'reception_erreur_emplacement', c.tracking_interne, { attendu: choix.case, scanne: scannee });
        return res.json({ ok: false, error: 'mauvais_emplacement', attendu: choix.case, scanne: scannee });
      }
      const laCase = choix.case;
      const { data, error } = await db.from('colis').update({ statut: 'disponible' }).eq('id', c.id).select().maybeSingle();
      if (error || !data) return res.json({ ok: false, error: 'update_failed' });
      const rCase = await db.from('colis').update({ case_congo: laCase }).eq('id', c.id);
      if (rCase.error) console.warn('case_congo non enregistrée (colonne manquante ?) :', rCase.error.message);
      if (c.statut === 'expedie') await noterEtapeTiinda(c.id, 'arrive');
      await noterEtapeTiinda(c.id, 'disponible');
      if (c.client_id) notifyColisStatus(c.client_id, data).catch(() => {});
      await journal(req.op, 'reception', c.tracking_interne, { case: laCase });
      res.json({ ok: true, meme_client: choix.meme_client, colis: ficheColis(Object.assign({}, c, { statut: 'disponible', case_congo: laCase, disponible_at: now(), jours: 0 })) });
    } catch (err) { erreurServeur(res, 'reception', err); }
  });

  /* Colis en boutique (disponibles), les plus anciens en premier. */
  app.get('/op/boutique', requireOp, async (req, res) => {
    try {
      let r = await db.from('colis').select(SELECT_COLIS).eq('statut', 'disponible').order('disponible_at', { ascending: true }).limit(500);
      if (r.error) r = await db.from('colis').select(SELECT_COLIS.replace(', case_congo', '')).eq('statut', 'disponible').order('disponible_at', { ascending: true }).limit(500);
      const a = await db.from('colis').select(SELECT_COLIS.replace(', case_congo', '')).eq('statut', 'expedie').order('expedie_at', { ascending: true }).limit(300);
      res.json({ ok: true, en_boutique: (r.data || []).map(ficheColis), a_recevoir: (a.data || []).map(ficheColis) });
    } catch (err) { erreurServeur(res, 'boutique', err); }
  });

  /* Chiffres du jour pour le panneau de droite du comptoir. */
  app.get('/op/jour', requireOp, async (req, res) => {
    try {
      const debut = debutJourBzv();
      const il7j = new Date(Date.now() - 7 * 86400000).toISOString();
      const nb = async (q) => { const r = await q; return r.error ? 0 : (r.count || 0); };
      const [remis, boutique, aRecevoir, relances, recharges, borne] = await Promise.all([
        nb(db.from('colis').select('id', { count: 'exact', head: true }).eq('statut', 'livre').gte('livre_at', debut)),
        nb(db.from('colis').select('id', { count: 'exact', head: true }).eq('statut', 'disponible')),
        nb(db.from('colis').select('id', { count: 'exact', head: true }).eq('statut', 'expedie')),
        db.from('colis').select(SELECT_COLIS.replace(', case_congo', '')).eq('statut', 'disponible').lt('disponible_at', il7j).order('disponible_at', { ascending: true }).limit(8),
        db.from('recharges_operateur').select('montant_fcfa, statut').gte('created_at', debut).neq('statut', 'refuse'),
        db.from('borne_depots').select('montant_fcfa').gte('depose_le', debut),
      ]);
      const enc = (recharges.data || []).reduce((s, x) => s + Number(x.montant_fcfa || 0), 0)
        + (borne.data || []).reduce((s, x) => s + Number(x.montant_fcfa || 0), 0);
      res.json({ ok: true, remis, en_boutique: boutique, a_recevoir: aRecevoir, encaisse_fcfa: enc, relances: (relances.data || []).map(ficheColis) });
    } catch (err) { erreurServeur(res, 'jour', err); }
  });

  /* ── Caisse : recharge de solde ──────────────────────────────────────── */
  app.get('/op/client', requireOp, async (req, res) => {
    try {
      const tel = normTel(req.query.tel);
      if (!tel || tel.length < 10) return res.json({ ok: false, error: 'tel_invalide' });
      const { data: cli } = await db.from('clients').select('id, prenom, nom, offre, wallet_balance, created_at').eq('phone', tel).maybeSingle();
      if (!cli) return res.json({ ok: true, tel, connu: false });
      res.json({ ok: true, tel, connu: true, client: { nom: [cli.prenom, cli.nom].filter(Boolean).join(' '), forfait: cli.offre || '', solde: Number(cli.wallet_balance || 0), depuis: cli.created_at } });
    } catch (err) { erreurServeur(res, 'client', err); }
  });

  async function numeroRecu(prefixe, table, colDate) {
    const j = jourParis().replace(/-/g, '').slice(2);
    const r = await db.from(table).select('id', { count: 'exact', head: true }).gte(colDate, debutJourBzv());
    return prefixe + '-' + j + '-' + String((r.count || 0) + 1).padStart(4, '0') + aleatoire(1, '0123456789');
  }

  /* L'agent encaisse : la demande part chez James, qui envoie le code par SMS au client. */
  app.post('/op/recharge', requireOp, async (req, res) => {
    try {
      const b = req.body || {};
      const tel = normTel(b.telephone);
      const montant = Math.round(Number(b.montant_fcfa || 0));
      const moyen = MOYENS[b.moyen] ? b.moyen : 'especes';
      const refPaiement = String(b.reference || '').trim().replace(/[^A-Za-z0-9.\-_ ]/g, '').slice(0, 40);
      const especes = moyen === 'especes' ? Math.round(Number(b.especes_recues || 0)) : Math.round(Number(b.montant_fcfa || 0));
      if (!tel || tel.length < 10) return res.json({ ok: false, error: 'tel_invalide' });
      if (!(montant >= 500)) return res.json({ ok: false, error: 'montant_trop_petit' });
      if (montant > 2000000) return res.json({ ok: false, error: 'montant_trop_grand' });
      if (moyen === 'especes' && especes < montant) return res.json({ ok: false, error: 'especes_insuffisantes' });
      if (moyen !== 'especes' && refPaiement.length < 4) return res.json({ ok: false, error: 'reference_requise' });
      const { data: cli } = await db.from('clients').select('id, prenom, nom').eq('phone', tel).maybeSingle();
      const nom = cli ? [cli.prenom, cli.nom ? String(cli.nom).charAt(0) + '.' : ''].filter(Boolean).join(' ') : String(b.nom || '').trim().slice(0, 60);
      const ligne = {
        numero: await numeroRecu('RCH', 'recharges_operateur', 'created_at'),
        operateur_id: req.op.id, client_id: cli ? cli.id : null, telephone: tel, nom_client: nom || null,
        montant_fcfa: montant, montant_eur: creditPourFcfa(montant), especes_recues: especes, monnaie_rendue: especes - montant,
        statut: 'attente',
      };
      /* Moyen de paiement : prévu pour plus tard (colonnes Supabase à créer). Pour l'instant tout est en espèces. */
      if (moyen !== 'especes') { ligne.moyen_paiement = moyen; ligne.ref_paiement = refPaiement || null; }
      let { data, error } = await db.from('recharges_operateur').insert(ligne).select().single();
      if (error && /moyen_paiement|ref_paiement/.test(error.message || '')) {
        /* Colonnes pas encore créées dans Supabase : on enregistre quand même (espèces seulement). */
        if (moyen !== 'especes') return res.json({ ok: false, error: 'mobile_money_pas_active' });
        delete ligne.moyen_paiement; delete ligne.ref_paiement;
        ({ data, error } = await db.from('recharges_operateur').insert(ligne).select().single());
      }
      if (error) { console.error('op recharge insert:', error.message); return res.json({ ok: false, error: 'enregistrement_impossible' }); }
      await journal(req.op, 'recharge', data.numero, { montant_fcfa: montant, moyen });
      res.json({ ok: true, recu: Object.assign({}, data, { moyen_paiement: moyen, ref_paiement: refPaiement || null, moyen_libelle: MOYENS[moyen], telephone_masque: masquerTel(tel), operateur: req.op.nom || req.op.identifiant, client_connu: !!cli }) });
    } catch (err) { erreurServeur(res, 'recharge', err); }
  });

  /* Opérations du jour (recharges + borne) et total en caisse. */
  app.get('/op/caisse', requireOp, async (req, res) => {
    try {
      const debut = debutJourBzv();
      const [rc, br] = await Promise.all([
        db.from('recharges_operateur').select('*').gte('created_at', debut).order('created_at', { ascending: false }),
        db.from('borne_depots').select('place, montant_fcfa, depose_le, rendu_le, code_ticket').gte('depose_le', debut).order('depose_le', { ascending: false }),
      ]);
      const recharges = (rc.data || []);
      const borne = (br.data || []);
      const valides = recharges.filter((x) => x.statut !== 'refuse');
      const totRc = valides.reduce((s, x) => s + Number(x.montant_fcfa || 0), 0);
      const mobiles = valides.filter((x) => x.moyen_paiement && x.moyen_paiement !== 'especes');
      const totMobile = mobiles.reduce((s, x) => s + Number(x.montant_fcfa || 0), 0);
      const totBr = borne.reduce((s, x) => s + Number(x.montant_fcfa || 0), 0);
      const ops = recharges.map((x) => ({ heure: x.created_at, type: 'recharge', libelle: (x.nom_client || masquerTel(x.telephone)), statut: x.statut, montant_fcfa: x.montant_fcfa, ref: x.numero, moyen: x.moyen_paiement || 'especes' }))
        .concat(borne.map((x) => ({ heure: x.depose_le, type: 'borne', libelle: 'Borne, place ' + x.place, statut: x.rendu_le ? 'rendu' : 'en_charge', montant_fcfa: x.montant_fcfa, ref: x.code_ticket })))
        .sort((a, b) => (a.heure < b.heure ? 1 : -1));
      res.json({ ok: true, total_fcfa: totRc + totBr, especes_fcfa: totRc - totMobile + totBr, mobile_fcfa: totMobile, mobile_nb: mobiles.length, recharges: { nb: valides.length, total_fcfa: totRc }, borne: { nb: borne.length, total_fcfa: totBr }, operations: ops.slice(0, 60) });
    } catch (err) { erreurServeur(res, 'caisse', err); }
  });

  /* Clôture : l'agent compte les espèces, le serveur compare au total attendu. */
  app.post('/op/cloture', requireOp, async (req, res) => {
    try {
      const b = req.body || {};
      const debut = debutJourBzv();
      const [rc, br] = await Promise.all([
        db.from('recharges_operateur').select('*').gte('created_at', debut).neq('statut', 'refuse'),
        db.from('borne_depots').select('montant_fcfa').gte('depose_le', debut),
      ]);
      /* Seules les espèces sont dans le tiroir : le Mobile Money est arrivé sur le compte. */
      const attendu = (rc.data || []).filter((x) => !x.moyen_paiement || x.moyen_paiement === 'especes').reduce((s, x) => s + Number(x.montant_fcfa || 0), 0) + (br.data || []).reduce((s, x) => s + Number(x.montant_fcfa || 0), 0);
      const fond = Math.round(Number(b.fond_fcfa || 0));
      const compte = Math.round(Number(b.especes_comptees || 0));
      const ecart = compte - fond - attendu;
      const { data, error } = await db.from('caisse_clotures').insert({ operateur_id: req.op.id, jour: jourParis(), fond_fcfa: fond, attendu_fcfa: attendu, compte_fcfa: compte, ecart_fcfa: ecart }).select().single();
      if (error) return res.json({ ok: false, error: 'enregistrement_impossible' });
      await journal(req.op, 'cloture', jourParis(), { attendu, compte, ecart });
      res.json({ ok: true, cloture: Object.assign({}, data, { operateur: req.op.nom || req.op.identifiant }) });
    } catch (err) { erreurServeur(res, 'cloture', err); }
  });

  /* ── Borne de recharge de téléphones ─────────────────────────────────── */
  app.get('/op/borne', requireOp, async (req, res) => {
    try {
      const debut = debutJourBzv();
      const [occ, auj] = await Promise.all([
        db.from('borne_depots').select('place, depose_le, code_ticket, telephone').is('rendu_le', null).order('depose_le', { ascending: true }),
        db.from('borne_depots').select('montant_fcfa').gte('depose_le', debut),
      ]);
      const occupees = (occ.data || []).map((x) => ({ place: x.place, depose_le: x.depose_le, heures: Math.floor((Date.now() - new Date(x.depose_le).getTime()) / 3600000) }));
      res.json({ ok: true, nb_places: NB_PLACES_BORNE, prix_fcfa: PRIX_BORNE_FCFA, occupees, deposes_aujourdhui: (auj.data || []).length, encaisse_fcfa: (auj.data || []).reduce((s, x) => s + Number(x.montant_fcfa || 0), 0) });
    } catch (err) { erreurServeur(res, 'borne', err); }
  });

  app.post('/op/borne/depot', requireOp, async (req, res) => {
    try {
      const b = req.body || {};
      const place = parseInt(b.place, 10);
      if (!(place >= 1 && place <= NB_PLACES_BORNE)) return res.json({ ok: false, error: 'place_invalide' });
      const { data: prise } = await db.from('borne_depots').select('id').eq('place', place).is('rendu_le', null).maybeSingle();
      if (prise) return res.json({ ok: false, error: 'place_occupee' });
      const tel = b.telephone ? normTel(b.telephone) : null;
      const ligne = { place, telephone: tel, code_ticket: 'BRN-' + aleatoire(6), montant_fcfa: PRIX_BORNE_FCFA, operateur_id: req.op.id };
      const { data, error } = await db.from('borne_depots').insert(ligne).select().single();
      if (error) return res.json({ ok: false, error: /duplicate|unique/i.test(error.message) ? 'place_occupee' : 'enregistrement_impossible' });
      await journal(req.op, 'borne_depot', data.code_ticket, { place });
      res.json({ ok: true, ticket: Object.assign({}, data, { operateur: req.op.nom || req.op.identifiant }) });
    } catch (err) { erreurServeur(res, 'borne depot', err); }
  });

  /* Rendre : scan du ticket (code-barres) ou numéro de place si ticket perdu. */
  app.post('/op/borne/rendre', requireOp, async (req, res) => {
    try {
      const b = req.body || {};
      const saisie = String(b.code || '').trim();
      let q = db.from('borne_depots').select('*').is('rendu_le', null);
      if (/^\d{1,2}$/.test(saisie)) q = q.eq('place', parseInt(saisie, 10));
      else q = q.eq('code_ticket', normCode(saisie));
      const { data: dep } = await q.maybeSingle();
      if (!dep) return res.json({ ok: false, error: 'ticket_introuvable' });
      await db.from('borne_depots').update({ rendu_le: now(), rendu_par: req.op.id, ticket_perdu: /^\d{1,2}$/.test(saisie) }).eq('id', dep.id);
      await journal(req.op, 'borne_rendu', dep.code_ticket, { place: dep.place, ticket_perdu: /^\d{1,2}$/.test(saisie) });
      res.json({ ok: true, place: dep.place });
    } catch (err) { erreurServeur(res, 'borne rendre', err); }
  });

  /* ── James : comptes agents ──────────────────────────────────────────── */
  app.get('/admin/operateurs', requireAdmin, async (req, res) => {
    try {
      const { data } = await db.from('operateurs').select('id, identifiant, nom, agence, actif, active_le, derniere_connexion, activation_expire, created_at').order('created_at', { ascending: true });
      res.json({ ok: true, operateurs: (data || []).filter((o) => !String(o.identifiant).startsWith('supprime.')) });
    } catch (err) { erreurServeur(res, 'admin operateurs', err); }
  });

  async function nouveauCodeActivation(id) {
    const code = aleatoire(4) + '-' + aleatoire(4);
    await db.from('operateurs').update({
      activation_hash: sha(code), activation_expire: new Date(Date.now() + ACTIVATION_MS).toISOString(),
      mdp_hash: null, totp_secret: null, totp_secret_tmp: null, dernier_compteur: 0, active_le: null,
    }).eq('id', id);
    return code;
  }

  app.post('/admin/operateurs', requireAdmin, async (req, res) => {
    try {
      const b = req.body || {};
      const ident = String(b.identifiant || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '');
      if (ident.length < 3) return res.json({ ok: false, error: 'identifiant_invalide' });
      const { data, error } = await db.from('operateurs').insert({ identifiant: ident, nom: String(b.nom || '').trim().slice(0, 60) || ident, agence: String(b.agence || 'Brazzaville').slice(0, 40), actif: true }).select().single();
      if (error) return res.json({ ok: false, error: /duplicate|unique/i.test(error.message) ? 'identifiant_pris' : 'creation_impossible' });
      const code = await nouveauCodeActivation(data.id);
      res.json({ ok: true, identifiant: ident, code_activation: code, expire_dans_h: 48 });
    } catch (err) { erreurServeur(res, 'admin creer operateur', err); }
  });

  // Mot de passe oublié ou téléphone perdu : nouveau code d'activation, ancien accès coupé.
  app.post('/admin/operateurs/reset', requireAdmin, async (req, res) => {
    try {
      const code = await nouveauCodeActivation(req.body && req.body.id);
      res.json({ ok: true, code_activation: code, expire_dans_h: 48 });
    } catch (err) { erreurServeur(res, 'admin reset operateur', err); }
  });

  app.post('/admin/operateurs/actif', requireAdmin, async (req, res) => {
    try {
      await db.from('operateurs').update({ actif: !!(req.body || {}).actif }).eq('id', (req.body || {}).id);
      res.json({ ok: true });
    } catch (err) { erreurServeur(res, 'admin actif operateur', err); }
  });

  /* Supprimer un agent. Il faut renvoyer son identifiant exact (confirmation).
     S'il a déjà fait des opérations, son compte est archivé : il disparaît de la
     liste et ne peut plus se connecter, mais l'historique (recharges, borne,
     clôtures, journal) reste lisible pour les contrôles. */
  app.post('/admin/operateurs/supprimer', requireAdmin, async (req, res) => {
    try {
      const b = req.body || {};
      const { data: op } = await db.from('operateurs').select('id, identifiant').eq('id', b.id).maybeSingle();
      if (!op) return res.json({ ok: false, error: 'introuvable' });
      if (String(b.confirmation || '').trim().toLowerCase() !== op.identifiant) return res.json({ ok: false, error: 'confirmation_incorrecte' });
      const { error } = await db.from('operateurs').delete().eq('id', op.id);
      if (!error) return res.json({ ok: true, archive: false });
      const { error: e2 } = await db.from('operateurs').update({
        actif: false, identifiant: 'supprime.' + op.id.slice(0, 8) + '.' + op.identifiant,
        mdp_hash: null, totp_secret: null, totp_secret_tmp: null, activation_hash: null, activation_expire: null,
      }).eq('id', op.id);
      if (e2) return res.json({ ok: false, error: 'suppression_impossible' });
      res.json({ ok: true, archive: true });
    } catch (err) { erreurServeur(res, 'admin supprimer operateur', err); }
  });

  /* ── James : demandes de recharge ────────────────────────────────────── */
  app.get('/admin/recharges-op', requireAdmin, async (req, res) => {
    try {
      let q = db.from('recharges_operateur').select('*, operateurs(nom, identifiant)').order('created_at', { ascending: false }).limit(200);
      if (req.query.statut) q = q.eq('statut', req.query.statut);
      const { data } = await q;
      res.json({ ok: true, demandes: data || [] });
    } catch (err) { erreurServeur(res, 'admin recharges', err); }
  });

  // Crée un code de recharge réservé au numéro du client et l'envoie par SMS.
  app.post('/admin/recharges-op/envoyer', requireAdmin, async (req, res) => {
    try {
      const id = (req.body || {}).id;
      const { data: dem } = await db.from('recharges_operateur').select('*').eq('id', id).maybeSingle();
      if (!dem) return res.json({ ok: false, error: 'introuvable' });
      if (dem.statut !== 'attente') return res.json({ ok: false, error: 'deja_traitee', statut: dem.statut });
      // Verrou : une seule personne traite la demande, même en double clic.
      const { data: pris } = await db.from('recharges_operateur').update({ statut: 'envoi' }).eq('id', id).eq('statut', 'attente').select('id');
      if (!pris || !pris.length) return res.json({ ok: false, error: 'deja_traitee' });
      const code = 'TND-' + aleatoire(4) + '-' + aleatoire(4);
      let ins = await db.from('recharge_codes').insert({ code, montant: dem.montant_eur, reserve_tel: dem.telephone }).select().single();
      if (ins.error && /reserve_tel/.test(ins.error.message || '')) ins = await db.from('recharge_codes').insert({ code, montant: dem.montant_eur }).select().single();
      if (ins.error) {
        await db.from('recharges_operateur').update({ statut: 'attente' }).eq('id', id);
        return res.json({ ok: false, error: 'code_impossible' });
      }
      const montantTxt = Number(dem.montant_eur).toFixed(2).replace('.', ',') + ' €';
      const texte = 'Tiinda : votre code de recharge de ' + montantTxt + ' est ' + code
        + '. Saisissez-le dans votre espace sur tiinda.com (Mon solde). Reçu ' + dem.numero + '.';
      let smsOk = false, smsErreur = null;
      if (process.env.TWILIO_SMS_FROM) {
        try { await twilio.messages.create({ from: process.env.TWILIO_SMS_FROM, to: dem.telephone, body: texte }); smsOk = true; }
        catch (e) { smsErreur = e.message; console.error('sms recharge op:', e.message); }
      } else smsErreur = 'TWILIO_SMS_FROM non configuré';
      await db.from('recharges_operateur').update({ statut: 'envoye', code, envoye_le: now(), sms_ok: smsOk }).eq('id', id);
      res.json({ ok: true, code, sms_ok: smsOk, sms_erreur: smsErreur, texte });
    } catch (err) { erreurServeur(res, 'admin envoyer recharge', err); }
  });

  app.post('/admin/recharges-op/refuser', requireAdmin, async (req, res) => {
    try {
      const b = req.body || {};
      const { data } = await db.from('recharges_operateur').update({ statut: 'refuse', motif_refus: String(b.motif || '').slice(0, 200) }).eq('id', b.id).eq('statut', 'attente').select('id');
      if (!data || !data.length) return res.json({ ok: false, error: 'deja_traitee' });
      res.json({ ok: true });
    } catch (err) { erreurServeur(res, 'admin refuser recharge', err); }
  });

  console.log('Espace opérateur Brazzaville : routes /op/* branchées');
};
