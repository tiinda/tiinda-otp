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
  /* Début de la journée de caisse : la dernière clôture (on bascule sur la journée suivante dès qu'on clôture),
     ou à défaut minuit (heure de Brazzaville). */
  async function debutCaisse() {
    const depuis = new Date(Date.now() - 45 * 86400000).toISOString();
    const { data } = await db.from('caisse_clotures').select('created_at').gte('created_at', depuis).limit(500);
    const derniere = (data || []).map((x) => x.created_at).filter(Boolean).sort().pop();
    return derniere || debutJourBzv();
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
    req.op = op; noterPresence(op); next();
  }

  /* Pointage : la première requête du jour = arrivée ; chaque requête (la page se rafraîchit
     toutes les 30 s) met à jour la dernière activité ; la déconnexion note le départ. */
  const PRESENCE_MAJ_MS = 60000, PRESENT_SI_MS = 3 * 60000;
  const derniereNote = new Map();
  async function noterPresence(op, quoi) {
    try {
      const t = Date.now(), cle = op.id + ':' + jourParis();
      if (!quoi && derniereNote.has(cle) && t - derniereNote.get(cle) < PRESENCE_MAJ_MS) return;
      derniereNote.set(cle, t);
      const jour = jourParis(), maintenant = new Date(t).toISOString();
      const { data: l } = await db.from('op_presences').select('id, nb_connexions, depart').eq('operateur_id', op.id).eq('jour', jour).maybeSingle();
      if (!l) {
        await db.from('op_presences').insert({ operateur_id: op.id, jour, arrivee: maintenant, derniere_activite: maintenant, nb_connexions: quoi === 'connexion' ? 1 : 0, depart: quoi === 'depart' ? maintenant : null });
        return;
      }
      const maj = { derniere_activite: maintenant };
      if (quoi === 'connexion') { maj.nb_connexions = (l.nb_connexions || 0) + 1; maj.depart = null; }
      if (quoi === 'depart') maj.depart = maintenant;
      await db.from('op_presences').update(maj).eq('id', l.id);
    } catch (e) { /* le pointage ne doit jamais bloquer l'agent */ }
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
      await noterPresence(op, 'connexion');
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
      const debut = debutJourBzv(), caisse = await debutCaisse();
      const il7j = new Date(Date.now() - 7 * 86400000).toISOString();
      const nb = async (q) => { const r = await q; return r.error ? 0 : (r.count || 0); };
      const [remis, boutique, aRecevoir, relances, recharges, borne] = await Promise.all([
        nb(db.from('colis').select('id', { count: 'exact', head: true }).eq('statut', 'livre').gte('livre_at', debut)),
        nb(db.from('colis').select('id', { count: 'exact', head: true }).eq('statut', 'disponible')),
        nb(db.from('colis').select('id', { count: 'exact', head: true }).eq('statut', 'expedie')),
        db.from('colis').select(SELECT_COLIS.replace(', case_congo', '')).eq('statut', 'disponible').lt('disponible_at', il7j).order('disponible_at', { ascending: true }).limit(8),
        db.from('recharges_operateur').select('montant_fcfa, statut').gt('created_at', caisse).neq('statut', 'refuse'),
        db.from('borne_depots').select('montant_fcfa').gt('depose_le', caisse),
      ]);
      const enc = (recharges.data || []).reduce((s, x) => s + Number(x.montant_fcfa || 0), 0)
        + (borne.data || []).reduce((s, x) => s + Number(x.montant_fcfa || 0), 0);
      res.json({ ok: true, remis, en_boutique: boutique, a_recevoir: aRecevoir, encaisse_fcfa: enc, relances: (relances.data || []).map(ficheColis) });
    } catch (err) { erreurServeur(res, 'jour', err); }
  });

  /* Indicateurs du tableau de bord : clients du jour, opérations, activité de la semaine, alertes. */
  app.get('/op/tableau', requireOp, async (req, res) => {
    try {
      const [y, m, d] = jourParis().split('-').map(Number);
      const dow = (new Date(Date.UTC(y, m - 1, d)).getUTCDay() + 6) % 7; // 0 = lundi
      const lundi = Date.UTC(y, m - 1, d - dow) - 3600000;
      const debutSem = new Date(lundi).toISOString(), debut = debutJourBzv();
      const il7j = new Date(Date.now() - 7 * 86400000).toISOString();
      const nb = async (q) => { const r = await q; return r.error ? 0 : (r.count || 0); };
      const [rc, br, livres, nouveaux, relances, attente, aRecevoir, rangement, borneOcc] = await Promise.all([
        db.from('recharges_operateur').select('client_id, telephone, montant_fcfa, statut, created_at').gte('created_at', debutSem),
        db.from('borne_depots').select('montant_fcfa, depose_le').gte('depose_le', debutSem),
        db.from('colis').select('client_id').eq('statut', 'livre').gte('livre_at', debut),
        nb(db.from('clients').select('id', { count: 'exact', head: true }).gte('created_at', debut)),
        nb(db.from('colis').select('id', { count: 'exact', head: true }).eq('statut', 'disponible').lt('disponible_at', il7j)),
        nb(db.from('recharges_operateur').select('id', { count: 'exact', head: true }).eq('statut', 'attente')),
        nb(db.from('colis').select('id', { count: 'exact', head: true }).eq('statut', 'expedie')),
        db.from('colis').select('case_congo').eq('statut', 'disponible').limit(5000),
        nb(db.from('borne_depots').select('id', { count: 'exact', head: true }).is('rendu_le', null)),
      ]);
      const casesPrises = new Set((rangement.data || []).map((x) => x.case_congo).filter((c) => c && EMPLACEMENTS.includes(c)));
      const recharges = (rc.data || []).filter((x) => x.statut !== 'refuse'), borne = br.data || [];
      const semaine = [0, 0, 0, 0, 0, 0, 0];
      const jourIdx = (iso) => Math.floor((new Date(iso).getTime() - lundi) / 86400000);
      recharges.forEach((x) => { const i = jourIdx(x.created_at); if (i >= 0 && i < 7) semaine[i] += Number(x.montant_fcfa || 0); });
      borne.forEach((x) => { const i = jourIdx(x.depose_le); if (i >= 0 && i < 7) semaine[i] += Number(x.montant_fcfa || 0); });
      const rcJour = recharges.filter((x) => x.created_at >= debut), brJour = borne.filter((x) => x.depose_le >= debut);
      const clients = new Set();
      rcJour.forEach((x) => clients.add(x.client_id || 'tel:' + x.telephone));
      (livres.data || []).forEach((x) => { if (x.client_id) clients.add(x.client_id); });
      const sem = await etatSemaine().catch(() => null);
      const { data: corr } = await db.from('caisse_clotures').select('id').eq('correction_autorisee', true).limit(20);
      res.json({
        ok: true, jour_semaine: dow, semaine_fcfa: semaine,
        clients_jour: clients.size, nouveaux_clients: nouveaux,
        operations_jour: rcJour.length + brJour.length + (livres.data || []).length,
        alertes: { a_receptionner: aRecevoir, colis_plus_7j: relances, recharges_attente: attente, semaine_a_cloturer: !!(sem && sem.a_cloturer && !sem.depot), depot: sem ? sem.depot : null, corrections: (corr || []).length },
        libres: { borne: Math.max(0, NB_PLACES_BORNE - borneOcc), borne_total: NB_PLACES_BORNE, rangement: EMPLACEMENTS.length - casesPrises.size, rangement_total: EMPLACEMENTS.length },
      });
    } catch (err) { erreurServeur(res, 'tableau', err); }
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

  /* Vérifier un reçu de recharge (scan du code-barres RCH-…) : le code a-t-il été envoyé au client, et utilisé ?
     Le code lui-même n'est jamais montré à l'agent. */
  app.get('/op/recu', requireOp, async (req, res) => {
    try {
      const n = String(req.query.n || '').trim().toUpperCase().replace(/[^A-Z0-9-]/g, '');
      if (!/^RCH-/.test(n)) return res.json({ ok: false, error: 'recu_introuvable' });
      const { data: d } = await db.from('recharges_operateur').select('*').eq('numero', n).maybeSingle();
      if (!d) return res.json({ ok: false, error: 'recu_introuvable' });
      let utilise = false, utilise_le = null;
      if (d.code) {
        const { data: rc } = await db.from('recharge_codes').select('used, used_at').eq('code', d.code).maybeSingle();
        if (rc) { utilise = !!rc.used; utilise_le = rc.used_at || null; }
      }
      res.json({ ok: true, recu: { numero: d.numero, statut: d.statut, montant_fcfa: d.montant_fcfa, montant_eur: d.montant_eur, nom_client: d.nom_client, telephone_masque: masquerTel(d.telephone), cree_le: d.created_at, envoye_le: d.envoye_le || null, message_parti: d.sms_ok !== false, motif_refus: d.motif_refus || null, utilise, utilise_le } });
    } catch (err) { erreurServeur(res, 'recu', err); }
  });

  /* Opérations du jour (recharges + borne) et total en caisse. */
  app.get('/op/caisse', requireOp, async (req, res) => {
    try {
      const debut = await debutCaisse();
      const [rc, br] = await Promise.all([
        db.from('recharges_operateur').select('*').gt('created_at', debut).order('created_at', { ascending: false }),
        db.from('borne_depots').select('place, montant_fcfa, depose_le, rendu_le, code_ticket').gt('depose_le', debut).order('depose_le', { ascending: false }),
      ]);
      const { data: epiV } = await db.from('epi_ventes').select('numero, total_fcfa, created_at, nb_pieces').gt('created_at', debut).order('created_at', { ascending: false });
      const epi = epiV || [], totEpi = epi.reduce((s, x) => s + Number(x.total_fcfa || 0), 0);
      const recharges = (rc.data || []);
      const borne = (br.data || []);
      const valides = recharges.filter((x) => x.statut !== 'refuse');
      const totRc = valides.reduce((s, x) => s + Number(x.montant_fcfa || 0), 0);
      const mobiles = valides.filter((x) => x.moyen_paiement && x.moyen_paiement !== 'especes');
      const totMobile = mobiles.reduce((s, x) => s + Number(x.montant_fcfa || 0), 0);
      const totBr = borne.reduce((s, x) => s + Number(x.montant_fcfa || 0), 0);
      const ops = recharges.map((x) => ({ heure: x.created_at, type: 'recharge', libelle: (x.nom_client || masquerTel(x.telephone)), statut: x.statut, montant_fcfa: x.montant_fcfa, ref: x.numero, moyen: x.moyen_paiement || 'especes' }))
        .concat(borne.map((x) => ({ heure: x.depose_le, type: 'borne', libelle: 'Borne, place ' + x.place, statut: x.rendu_le ? 'rendu' : 'en_charge', montant_fcfa: x.montant_fcfa, ref: x.code_ticket })))
        .concat(epi.map((x) => ({ heure: x.created_at, type: 'epicerie', libelle: 'Épicerie, ' + x.nb_pieces + ' article(s)', statut: 'payee', montant_fcfa: x.total_fcfa, ref: x.numero })))
        .sort((a, b) => (a.heure < b.heure ? 1 : -1));
      res.json({ ok: true, depuis: debut, total_fcfa: totRc + totBr + totEpi, especes_fcfa: totRc - totMobile + totBr + totEpi, epicerie: { nb: epi.length, total_fcfa: totEpi }, mobile_fcfa: totMobile, mobile_nb: mobiles.length, recharges: { nb: valides.length, total_fcfa: totRc }, borne: { nb: borne.length, total_fcfa: totBr }, operations: ops.slice(0, 60) });
    } catch (err) { erreurServeur(res, 'caisse', err); }
  });

  /* ── Envoi d'une alerte à James : SMS (OP_ALERTE_TEL) + e-mail (ADMIN_EMAIL) ── */
  async function alerterJames(sujet, texte, html) {
    const h = horodatage();
    texte = texte + ' Le ' + h.texte + '.';
    html = (html || '<p>' + texte + '</p>') + '<p style="color:#4A5578;font-size:13px">Envoyé le ' + h.texte + '.</p>';
    const tel = process.env.OP_ALERTE_TEL;
    if (tel && process.env.TWILIO_SMS_FROM && twilio) {
      try { await twilio.messages.create({ from: process.env.TWILIO_SMS_FROM, to: tel, body: texte }); } catch (e) { console.warn('SMS alerte :', e.message); }
    }
    const mail = process.env.ADMIN_EMAIL, cle = process.env.RESEND_API_KEY;
    if (mail && cle) {
      try {
        await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + cle, 'Content-Type': 'application/json' },
          body: JSON.stringify({ from: process.env.MAIL_FROM || 'Tiinda <noreply@tiinda.com>', to: mail, subject: sujet, html: html || '<p>' + texte + '</p>' }) });
      } catch (e) { console.warn('e-mail alerte :', e.message); }
    }
  }
  /* Horodatage des alertes : date et heure de Brazzaville et de Paris (elles diffèrent en été). */
  function horodatage(d) {
    d = d || new Date();
    const jour = d.toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'Africa/Brazzaville' });
    const hB = d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Brazzaville' });
    const hP = d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Paris' });
    return { jour, hB, hP, texte: jour + ', ' + hB + ' heure de Brazzaville (' + hP + ' heure de Paris)' };
  }
  const jourLongDe = (j) => { const p = String(j).split('-').map(Number); return new Date(Date.UTC(p[0], p[1] - 1, p[2], 12)).toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }); };
  const fmtF = (n) => Math.round(Number(n || 0)).toLocaleString('fr-FR').replace(/ | /g, ' ');
  const fmtDate = (iso) => new Date(iso).toLocaleString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Brazzaville' });

  /* ── Clôture de semaine : les espèces de la semaine (compté − fond, jour par jour) sont à déposer en banque sous 48 h ── */
  const DELAI_DEPOT_H = 48;
  async function etatSemaine() {
    const { data: sems } = await db.from('caisse_semaines').select('*').order('created_at', { ascending: false }).limit(50);
    const liste = (sems || []).slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    const derniere = liste[0] || null;
    const depuis = derniere ? derniere.created_at : new Date(Date.now() - 60 * 86400000).toISOString();
    const { data: clos } = await db.from('caisse_clotures').select('*').gt('created_at', depuis);
    const jours = (clos || []).slice().sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
    const aDeposer = jours.reduce((t, c) => t + Math.max(0, Number(c.compte_fcfa || 0) - Number(c.fond_fcfa || 0)), 0);
    /* Il faut clôturer la semaine dès que la clôture du samedi est faite, ou si des jours d'une semaine passée restent ouverts. */
    const [y, m, d] = jourParis().split('-').map(Number);
    const dow = (new Date(Date.UTC(y, m - 1, d)).getUTCDay() + 6) % 7;
    const lundiIso = new Date(Date.UTC(y, m - 1, d - dow) - 3600000).toISOString();
    const samediClos = jours.some((c) => { const p = String(c.jour).split('-').map(Number); return new Date(Date.UTC(p[0], p[1] - 1, p[2])).getUTCDay() === 6; });
    const semainePassee = jours.some((c) => c.created_at < lundiIso);
    const enCours = liste.find((x) => x.statut === 'a_deposer') || null;
    let depot = null;
    if (enCours) {
      const resteMs = new Date(enCours.echeance).getTime() - Date.now();
      depot = { id: enCours.id, numero: enCours.numero, a_deposer_fcfa: enCours.a_deposer_fcfa, echeance: enCours.echeance, reste_h: Math.max(0, Math.floor(resteMs / 3600000)), en_retard: resteMs < 0 };
      if (depot.en_retard && !enCours.alerte_retard) {
        await db.from('caisse_semaines').update({ alerte_retard: true }).eq('id', enCours.id);
        alerterJames('⚠ Dépôt en banque en retard (Brazzaville)', 'Tiinda Brazzaville : RETARD de dépôt en banque. ' + fmtF(enCours.a_deposer_fcfa) + ' FCFA devaient être déposés avant ' + fmtDate(enCours.echeance) + ' (semaine ' + enCours.numero + ').').catch(() => {});
      }
    }
    return { a_cloturer: jours.length > 0 && (samediClos || semainePassee), jours, a_deposer_fcfa: aDeposer, depot };
  }

  app.get('/op/semaine', requireOp, async (req, res) => {
    try {
      const e = await etatSemaine();
      res.json({ ok: true, a_cloturer: e.a_cloturer, nb_jours: e.jours.length, a_deposer_fcfa: e.a_deposer_fcfa,
        jours: e.jours.map((c) => ({ jour: c.jour, encaisse_fcfa: c.attendu_fcfa, compte_fcfa: c.compte_fcfa, fond_fcfa: c.fond_fcfa, ecart_fcfa: c.ecart_fcfa })), depot: e.depot });
    } catch (err) { erreurServeur(res, 'semaine', err); }
  });

  app.post('/op/semaine/cloturer', requireOp, async (req, res) => {
    try {
      if (!rateLimit('op-sem:' + req.op.id, 10, 60000)) return res.status(429).json({ ok: false, error: 'trop_de_tentatives' });
      const e = await etatSemaine();
      if (!e.jours.length) return res.json({ ok: false, error: 'aucune_journee' });
      if (e.depot) return res.json({ ok: false, error: 'depot_en_attente' });
      const numero = 'SEM-' + jourParis().replace(/-/g, '').slice(2);
      const echeance = new Date(Date.now() + DELAI_DEPOT_H * 3600000).toISOString();
      const ligne = { operateur_id: req.op.id, numero, du: e.jours[0].jour, au: e.jours[e.jours.length - 1].jour, nb_jours: e.jours.length,
        encaisse_fcfa: e.jours.reduce((t, c) => t + Number(c.attendu_fcfa || 0), 0), ecarts_fcfa: e.jours.reduce((t, c) => t + Number(c.ecart_fcfa || 0), 0),
        a_deposer_fcfa: e.a_deposer_fcfa, echeance, statut: 'a_deposer' };
      const { data, error } = await db.from('caisse_semaines').insert(ligne).select().single();
      if (error || !data) return res.json({ ok: false, error: 'enregistrement_impossible' });
      await journal(req.op, 'cloture_semaine', numero, { a_deposer: e.a_deposer_fcfa });
      const nom = req.op.nom || req.op.identifiant;
      alerterJames('Clôture de semaine Brazzaville : ' + fmtF(e.a_deposer_fcfa) + ' FCFA à déposer',
        'Tiinda Brazzaville : semaine du ' + jourLongDe(ligne.du) + ' au ' + jourLongDe(ligne.au) + ' clôturée par ' + nom + '. ' + fmtF(e.a_deposer_fcfa) + ' FCFA à déposer en banque avant ' + fmtDate(echeance) + ' (heure de Brazzaville).').catch(() => {});
      res.json({ ok: true, semaine: Object.assign({}, data, { operateur: nom, jours: e.jours.map((c) => ({ jour: c.jour, compte_fcfa: c.compte_fcfa, fond_fcfa: c.fond_fcfa })) }) });
    } catch (err) { erreurServeur(res, 'cloture semaine', err); }
  });

  app.post('/op/semaine/depot', requireOp, async (req, res) => {
    try {
      if (!rateLimit('op-depot:' + req.op.id, 10, 60000)) return res.status(429).json({ ok: false, error: 'trop_de_tentatives' });
      const b = req.body || {};
      const { data: sem } = await db.from('caisse_semaines').select('*').eq('id', b.id).maybeSingle();
      if (!sem || sem.statut !== 'a_deposer') return res.json({ ok: false, error: 'depot_introuvable' });
      const montant = Math.round(Number(b.montant || 0));
      const bordereau = String(b.bordereau || '').trim().slice(0, 40);
      if (!(montant > 0)) return res.json({ ok: false, error: 'montant_requis' });
      if (bordereau.length < 3) return res.json({ ok: false, error: 'bordereau_requis' });
      const enRetard = Date.now() > new Date(sem.echeance).getTime();
      await db.from('caisse_semaines').update({ statut: 'depose', depose_fcfa: montant, bordereau, depose_le: now(), depose_par: req.op.id }).eq('id', sem.id);
      await journal(req.op, 'depot_banque', sem.numero, { montant, bordereau, en_retard: enRetard });
      const ecart = montant - Number(sem.a_deposer_fcfa || 0);
      alerterJames((ecart === 0 ? '' : '⚠ ') + 'Dépôt en banque Brazzaville : ' + fmtF(montant) + ' FCFA',
        'Tiinda Brazzaville : dépôt en banque de ' + fmtF(montant) + ' FCFA (bordereau ' + bordereau + ')' + (ecart === 0 ? '' : ', écart ' + fmtF(ecart) + ' FCFA sur ' + fmtF(sem.a_deposer_fcfa)) + (enRetard ? ', EN RETARD' : '') + '.').catch(() => {});
      res.json({ ok: true, ecart_fcfa: ecart, en_retard: enRetard });
    } catch (err) { erreurServeur(res, 'depot', err); }
  });

  /* ── Corrections de clôture : uniquement par le responsable, ou par l'agent quand le responsable l'a autorisé ── */
  async function corrigerCloture(id, b, auteur) {
    const { data: c } = await db.from('caisse_clotures').select('*').eq('id', id).maybeSingle();
    if (!c) return { ok: false, error: 'cloture_introuvable' };
    const fond = Math.max(0, Math.round(Number(b.fond_fcfa || 0)));
    const compte = Math.round(Number(b.especes_comptees));
    const banque = b.solde_banque === undefined || b.solde_banque === '' || b.solde_banque === null ? c.solde_banque_fcfa : Math.round(Number(b.solde_banque));
    if (!Number.isFinite(compte) || compte < 0) return { ok: false, error: 'montant_invalide' };
    const avant = { fond_fcfa: c.fond_fcfa, compte_fcfa: c.compte_fcfa, ecart_fcfa: c.ecart_fcfa, solde_banque_fcfa: c.solde_banque_fcfa };
    const ecart = compte - fond - Number(c.attendu_fcfa || 0);
    const historique = (Array.isArray(c.historique) ? c.historique : []).concat([{ le: now(), par: auteur, avant }]);
    const maj = { fond_fcfa: fond, compte_fcfa: compte, ecart_fcfa: ecart, solde_banque_fcfa: banque, correction_autorisee: false, modifiee_le: now(), historique };
    const { error } = await db.from('caisse_clotures').update(maj).eq('id', c.id);
    if (error) return { ok: false, error: 'enregistrement_impossible' };
    alerterJames('Clôture du ' + jourLongDe(c.jour) + ' corrigée',
      'Tiinda Brazzaville : clôture du ' + jourLongDe(c.jour) + ' corrigée par ' + auteur + '. Écart ' + fmtF(avant.ecart_fcfa) + ' -> ' + fmtF(ecart) + ' FCFA, compté ' + fmtF(avant.compte_fcfa) + ' -> ' + fmtF(compte) + ' FCFA.').catch(() => {});
    return { ok: true, cloture: Object.assign({}, c, maj) };
  }
  /* Agent : clôtures qu'il a le droit de corriger. */
  app.get('/op/clotures/corrigeables', requireOp, async (req, res) => {
    try {
      const { data } = await db.from('caisse_clotures').select('*').eq('correction_autorisee', true).limit(20);
      res.json({ ok: true, clotures: (data || []).map((c) => ({ id: c.id, jour: c.jour, fond_fcfa: c.fond_fcfa, attendu_fcfa: c.attendu_fcfa, compte_fcfa: c.compte_fcfa, ecart_fcfa: c.ecart_fcfa, solde_banque_fcfa: c.solde_banque_fcfa })) });
    } catch (err) { erreurServeur(res, 'corrigeables', err); }
  });
  app.post('/op/cloture/corriger', requireOp, async (req, res) => {
    try {
      const b = req.body || {};
      const { data: c } = await db.from('caisse_clotures').select('id, correction_autorisee').eq('id', b.id).maybeSingle();
      if (!c) return res.json({ ok: false, error: 'cloture_introuvable' });
      if (!c.correction_autorisee) return res.json({ ok: false, error: 'correction_non_autorisee' });
      const r = await corrigerCloture(c.id, b, 'agent ' + (req.op.nom || req.op.identifiant));
      if (r.ok) await journal(req.op, 'cloture_corrigee', r.cloture.jour, { ecart: r.cloture.ecart_fcfa });
      res.json(r);
    } catch (err) { erreurServeur(res, 'corriger', err); }
  });
  /* Responsable : toutes les clôtures, rangées par semaine, avec les dépôts en banque. */
  app.get('/admin/clotures', requireAdmin, async (req, res) => {
    try {
      const nbSem = Math.min(26, Math.max(1, parseInt(req.query.semaines || '8', 10) || 8));
      const depuis = new Date(Date.now() - nbSem * 7 * 86400000).toISOString();
      const [clo, sem, ops] = await Promise.all([
        db.from('caisse_clotures').select('*').gte('created_at', depuis),
        db.from('caisse_semaines').select('*').gte('created_at', depuis),
        db.from('operateurs').select('id, nom, identifiant'),
      ]);
      const nomOp = {}; (ops.data || []).forEach((o) => { nomOp[o.id] = o.nom || o.identifiant; });
      const lundiDe = (jour) => { const p = String(jour).split('-').map(Number); const d = new Date(Date.UTC(p[0], p[1] - 1, p[2])); d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7)); return d.toISOString().slice(0, 10); };
      const semaines = {};
      (clo.data || []).forEach((c) => {
        const k = lundiDe(c.jour); (semaines[k] = semaines[k] || { lundi: k, jours: [], depots: [] }).jours.push({
          id: c.id, jour: c.jour, operateur: nomOp[c.operateur_id] || '', fond_fcfa: c.fond_fcfa, attendu_fcfa: c.attendu_fcfa, compte_fcfa: c.compte_fcfa,
          ecart_fcfa: c.ecart_fcfa, solde_banque_fcfa: c.solde_banque_fcfa, correction_autorisee: !!c.correction_autorisee, modifiee_le: c.modifiee_le || null, nb_corrections: Array.isArray(c.historique) ? c.historique.length : 0 });
      });
      (sem.data || []).forEach((w) => {
        const k = lundiDe(w.au || w.du || String(w.created_at).slice(0, 10)); (semaines[k] = semaines[k] || { lundi: k, jours: [], depots: [] }).depots.push({
          numero: w.numero, du: w.du, au: w.au, a_deposer_fcfa: w.a_deposer_fcfa, echeance: w.echeance, statut: w.statut, depose_fcfa: w.depose_fcfa, bordereau: w.bordereau, depose_le: w.depose_le });
      });
      const liste = Object.values(semaines).sort((a, b) => b.lundi.localeCompare(a.lundi));
      liste.forEach((w) => { w.jours.sort((a, b) => a.jour.localeCompare(b.jour)); w.encaisse_fcfa = w.jours.reduce((t, c) => t + Number(c.attendu_fcfa || 0), 0); w.ecarts_fcfa = w.jours.reduce((t, c) => t + Number(c.ecart_fcfa || 0), 0); });
      res.json({ ok: true, semaines: liste });
    } catch (err) { erreurServeur(res, 'admin clotures', err); }
  });
  app.post('/admin/clotures/autoriser', requireAdmin, async (req, res) => {
    try {
      const b = req.body || {};
      const { error } = await db.from('caisse_clotures').update({ correction_autorisee: !!b.autoriser }).eq('id', b.id);
      res.json(error ? { ok: false, error: 'enregistrement_impossible' } : { ok: true });
    } catch (err) { erreurServeur(res, 'autoriser', err); }
  });
  app.post('/admin/clotures/modifier', requireAdmin, async (req, res) => {
    try { res.json(await corrigerCloture((req.body || {}).id, req.body || {}, 'le responsable')); } catch (err) { erreurServeur(res, 'admin modifier', err); }
  });

  /* Clôture : James est prévenu tout de suite, par e-mail (ADMIN_EMAIL) et par SMS (OP_ALERTE_TEL, ex. +33612345678).
     L'agent peut toujours clôturer, même avec un écart. */
  async function alerterCloture(op, c) {
    const f = (n) => Math.round(Number(n || 0)).toLocaleString('fr-FR').replace(/\u202f|\u00a0/g, ' ');
    const nom = op.nom || op.identifiant;
    const etat = c.ecart === 0 ? 'caisse juste' : (c.ecart < 0 ? 'MANQUE ' + f(-c.ecart) + ' FCFA' : 'SURPLUS ' + f(c.ecart) + ' FCFA');
    const h = horodatage(), jl = jourLongDe(c.jour || jourParis());
    const texte = 'Tiinda Brazzaville : clôture du ' + jl + ' (faite à ' + h.hB + ' Brazzaville, ' + h.hP + ' Paris) par ' + nom + ', ' + etat + '. Attendu ' + f(c.attendu) + ' FCFA, compté ' + f(c.compte) + ' FCFA (fond ' + f(c.fond) + '). Banque : ' + f(c.banque) + ' FCFA.';
    const tel = process.env.OP_ALERTE_TEL;
    if (tel && process.env.TWILIO_SMS_FROM && twilio) {
      try { await twilio.messages.create({ from: process.env.TWILIO_SMS_FROM, to: tel, body: texte }); } catch (e) { console.warn('SMS alerte clôture :', e.message); }
    }
    const mail = process.env.ADMIN_EMAIL, cle = process.env.RESEND_API_KEY;
    if (mail && cle) {
      const couleur = c.ecart === 0 ? '#0B7A4B' : '#B42318';
      await fetch('https://api.resend.com/emails', {
        method: 'POST', headers: { Authorization: 'Bearer ' + cle, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: process.env.MAIL_FROM || 'Tiinda <noreply@tiinda.com>', to: mail,
          subject: (c.ecart === 0 ? '' : '⚠ ') + 'Clôture du ' + jl + ' (Brazzaville) : ' + etat + ' (' + nom + ')',
          html: '<p><strong>Clôture de caisse du ' + jl + '</strong><br>Faite le ' + h.texte + '<br>par <strong>' + nom + '</strong>, agence Brazzaville.</p>'
            + '<table cellpadding="6" style="border-collapse:collapse;font-family:Arial,sans-serif">'
            + '<tr><td>Fond de caisse</td><td align="right">' + f(c.fond) + ' FCFA</td></tr>'
            + '<tr><td>Encaissé (attendu)</td><td align="right">' + f(c.attendu) + ' FCFA</td></tr>'
            + '<tr><td>Espèces comptées</td><td align="right">' + f(c.compte) + ' FCFA</td></tr>'
            + '<tr><td><strong>Écart</strong></td><td align="right" style="color:' + couleur + '"><strong>' + f(c.ecart) + ' FCFA</strong></td></tr>'
            + '<tr><td>Solde en banque (Congo)</td><td align="right"><strong>' + f(c.banque) + ' FCFA</strong><br><span style="font-size:11px;color:#9AA3B8">soit ' + (Number(c.banque || 0) / TAUX_FCFA).toFixed(2).replace('.', ',').replace(/\B(?=(\d{3})+(?!\d))/g, ' ') + ' €</span></td></tr></table>',
        }),
      });
    }
    return texte;
  }

  /* Clôture : l'agent compte les espèces, le serveur compare au total attendu. */
  app.post('/op/cloture', requireOp, async (req, res) => {
    try {
      const b = req.body || {};
      const debut = await debutCaisse();
      const [rc, br] = await Promise.all([
        db.from('recharges_operateur').select('*').gt('created_at', debut).neq('statut', 'refuse'),
        db.from('borne_depots').select('montant_fcfa').gt('depose_le', debut),
      ]);
      /* Seules les espèces sont dans le tiroir : le Mobile Money est arrivé sur le compte. */
      const { data: epiV } = await db.from('epi_ventes').select('total_fcfa, moyen_paiement').gt('created_at', debut);
      const especesEpi = (epiV || []).filter((x) => !x.moyen_paiement || x.moyen_paiement === 'especes').reduce((s, x) => s + Number(x.total_fcfa || 0), 0);
      const attendu = (rc.data || []).filter((x) => !x.moyen_paiement || x.moyen_paiement === 'especes').reduce((s, x) => s + Number(x.montant_fcfa || 0), 0) + (br.data || []).reduce((s, x) => s + Number(x.montant_fcfa || 0), 0) + especesEpi;
      const fond = Math.round(Number(b.fond_fcfa || 0));
      const compte = Math.round(Number(b.especes_comptees || 0));
      /* Une seule clôture par jour : ensuite, seul le responsable peut la corriger (ou autoriser l'agent à le faire). */
      const { data: dejaFaite } = await db.from('caisse_clotures').select('id').eq('jour', jourParis()).limit(1);
      if ((dejaFaite || []).length) return res.json({ ok: false, error: 'deja_cloturee' });
      const ecart = compte - fond - attendu;
      /* Solde du compte bancaire au Congo, renseigné chaque soir par l'agent (obligatoire). */
      if (b.solde_banque === undefined || b.solde_banque === null || String(b.solde_banque).trim() === '') return res.json({ ok: false, error: 'solde_banque_requis' });
      const banque = Math.round(Number(b.solde_banque));
      if (!Number.isFinite(banque) || banque < 0) return res.json({ ok: false, error: 'solde_banque_requis' });
      const ligne = { operateur_id: req.op.id, jour: jourParis(), fond_fcfa: fond, attendu_fcfa: attendu, compte_fcfa: compte, ecart_fcfa: ecart, solde_banque_fcfa: banque };
      let { data, error } = await db.from('caisse_clotures').insert(ligne).select().single();
      if (error && /solde_banque/.test(error.message || '')) {
        /* Colonne pas encore créée dans Supabase : on garde la clôture, le solde reste dans le journal et l'alerte. */
        delete ligne.solde_banque_fcfa;
        ({ data, error } = await db.from('caisse_clotures').insert(ligne).select().single());
        if (data) data.solde_banque_fcfa = banque;
      }
      if (error) return res.json({ ok: false, error: 'enregistrement_impossible' });
      await journal(req.op, 'cloture', jourParis(), { attendu, compte, ecart, banque });
      alerterCloture(req.op, { fond, attendu, compte, ecart, banque, jour: jourParis() }).catch((e) => console.warn('alerte clôture :', e.message));
      res.json({ ok: true, cloture: Object.assign({}, data, { operateur: req.op.nom || req.op.identifiant }) });
    } catch (err) { erreurServeur(res, 'cloture', err); }
  });


  /* ══ Épicerie (caisse de la boutique) ════════════════════════════════════
     Les prix sont dans la base, fixés par le responsable depuis sa page admin.
     La caisse envoie seulement produit + quantité : le serveur recalcule tout. */
  const RAYONS_EPI = ['Alimentation', 'Boissons', 'Hygiène', 'Frais', 'Services', 'Autre'];
  const normCodeEpi = (c) => String(c || '').replace(/\s+/g, '').slice(0, 40) || null;

  /* Liste pour la caisse. Connexion faible au Congo : si rien n'a changé depuis la dernière fois (?v=),
     on répond juste « inchangé » ; les photos ne sont jamais dans la liste, seulement leur adresse. */
  app.get('/op/epicerie/produits', requireOp, async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      const { data } = await db.from('epi_produits').select('id, nom, rayon, prix_fcfa, code_barres, rupture, image_url, actif, created_at, modifie_le').limit(10000);
      const tous = data || [];
      const v = tous.length + '-' + tous.reduce((m, x) => { const t = x.modifie_le || x.created_at || ''; return t > m ? t : m; }, '');
      const vCourt = crypto.createHash('sha1').update(v).digest('hex').slice(0, 10);
      if (req.query.v && req.query.v === vCourt) return res.json({ ok: true, inchange: true, v: vCourt });
      const produits = tous.filter((x) => x.actif).sort((a, b) => a.nom.localeCompare(b.nom, 'fr')).map((x) => ({
        id: x.id, nom: x.nom, rayon: x.rayon, prix_fcfa: x.prix_fcfa, code_barres: x.code_barres, rupture: x.rupture,
        image_url: !x.image_url ? null : /^data:/.test(x.image_url) ? '/epicerie/image/' + x.id + '?v=' + crypto.createHash('sha1').update(x.image_url).digest('hex').slice(0, 8) : x.image_url,
      }));
      res.json({ ok: true, v: vCourt, rayons: RAYONS_EPI, produits });
    } catch (err) { erreurServeur(res, 'epicerie produits', err); }
  });

  /* Photo gardée dans la fiche (si le stockage n'est pas disponible) : servie à part, gardée en cache un an par le navigateur. */
  app.get('/epicerie/image/:id', async (req, res) => {
    try {
      if (!db) return res.status(404).end();
      const { data } = await db.from('epi_produits').select('image_url').eq('id', req.params.id).maybeSingle();
      const m = data && /^data:(image\/(?:jpeg|png|webp));base64,(.+)$/.exec(data.image_url || '');
      if (!m) return res.status(404).end();
      res.set('Content-Type', m[1]); res.set('Cache-Control', 'public, max-age=31536000, immutable');
      res.send(Buffer.from(m[2], 'base64'));
    } catch (e) { res.status(404).end(); }
  });

  app.post('/op/epicerie/vente', requireOp, async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      if (!rateLimit('epi-vente:' + req.op.id, 60, 60000)) return res.status(429).json({ ok: false, error: 'trop_de_tentatives' });
      const b = req.body || {};
      const demandes = (Array.isArray(b.lignes) ? b.lignes : []).map((l) => ({ id: String(l.produit_id || ''), q: Math.floor(Number(l.quantite)) })).filter((l) => l.id && l.q > 0 && l.q <= 999);
      if (!demandes.length) return res.json({ ok: false, error: 'ticket_vide' });
      const { data: prods } = await db.from('epi_produits').select('id, nom, prix_fcfa, actif').in('id', demandes.map((d) => d.id));
      const P = {}; (prods || []).forEach((x) => { P[x.id] = x; });
      const lignes = [];
      for (const d of demandes) {
        const x = P[d.id];
        if (!x || !x.actif) return res.json({ ok: false, error: 'produit_inconnu', produit_id: d.id });
        lignes.push({ produit_id: x.id, nom: x.nom, prix_fcfa: Math.round(Number(x.prix_fcfa)), quantite: d.q, total_fcfa: Math.round(Number(x.prix_fcfa)) * d.q });
      }
      const total = lignes.reduce((t, l) => t + l.total_fcfa, 0);
      const recu = Math.round(Number(b.recu_fcfa || 0));
      if (recu < total) return res.json({ ok: false, error: 'montant_insuffisant', total_fcfa: total });
      const jour = jourParis();
      const { count } = await db.from('epi_ventes').select('id', { count: 'exact', head: true }).eq('jour', jour);
      const numero = 'EP-' + jour.slice(2).replace(/-/g, '') + '-' + String((count || 0) + 1).padStart(4, '0');
      const vente = { numero, jour, operateur_id: req.op.id, total_fcfa: total, recu_fcfa: recu, rendu_fcfa: recu - total, moyen_paiement: 'especes', nb_articles: lignes.length, nb_pieces: lignes.reduce((t, l) => t + l.quantite, 0) };
      const { data: v, error } = await db.from('epi_ventes').insert(vente).select().single();
      if (error || !v) return res.json({ ok: false, error: 'enregistrement_impossible' });
      await db.from('epi_lignes').insert(lignes.map((l) => Object.assign({ vente_id: v.id }, l)));
      await journal(req.op, 'epicerie_vente', numero, { total, nb: lignes.length });
      res.json({ ok: true, vente: Object.assign({}, v, { lignes, operateur: req.op.nom || req.op.identifiant }) });
    } catch (err) { erreurServeur(res, 'epicerie vente', err); }
  });

  /* Ticket annulé avant encaissement : rien n'est vendu, mais on le garde dans le journal. */
  app.post('/op/epicerie/annulation', requireOp, async (req, res) => {
    const b = req.body || {};
    await journal(req.op, 'epicerie_ticket_annule', null, { total: Math.round(Number(b.total_fcfa || 0)), nb: Math.round(Number(b.nb || 0)) });
    res.json({ ok: true });
  });

  /* ── Admin : produits et prix (modifiables depuis la France) ── */
  app.get('/admin/epicerie/produits', requireAdmin, async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      const { data } = await db.from('epi_produits').select('*').order('nom', { ascending: true }).limit(10000);
      res.json({ ok: true, rayons: RAYONS_EPI, produits: data || [] });
    } catch (err) { erreurServeur(res, 'admin epi produits', err); }
  });


  /* Photo d'un produit : adresse d'une image (Open Food Facts) ou photo prise sur place, réduite dans le navigateur.
     La photo va dans le stockage Supabase (dossier public « epicerie ») ; à défaut elle reste dans la fiche. */
  async function enregistrerImage(img) {
    img = String(img || '');
    if (!img) return null;
    if (/^https:\/\/[^\s"'<>]{5,500}$/.test(img)) return img;
    const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(img);
    if (!m || m[2].length > 55000) return null; /* environ 40 Ko maximum : les photos sont réduites dans le navigateur avant l'envoi */
    try {
      if (db.storage) {
        const nom = 'produits/' + crypto.randomBytes(8).toString('hex') + '.' + (m[1] === 'jpeg' ? 'jpg' : m[1]);
        const { error } = await db.storage.from('epicerie').upload(nom, Buffer.from(m[2], 'base64'), { contentType: 'image/' + m[1], upsert: false, cacheControl: '31536000' });
        if (!error) { const { data } = db.storage.from('epicerie').getPublicUrl(nom); if (data && data.publicUrl) return data.publicUrl; }
      }
    } catch (e) { console.warn('photo produit :', e.message); }
    return img;
  }

  /* Recherche d'un produit par son code-barres dans Open Food Facts (base publique et gratuite) : nom et photo. */
  app.get('/admin/epicerie/off', requireAdmin, async (req, res) => {
    try {
      const code = String(req.query.code || '').replace(/\D/g, '');
      if (code.length < 8) return res.json({ ok: false, error: 'code_invalide' });
      const r = await fetch('https://world.openfoodfacts.org/api/v2/product/' + code + '.json?fields=product_name,product_name_fr,brands,quantity,image_front_small_url,image_front_url', { headers: { 'User-Agent': 'Colispo-Epicerie/1.0 (contact@coolibo.com)' } });
      const j = await r.json().catch(() => ({}));
      if (!j || j.status !== 1 || !j.product) return res.json({ ok: false, error: 'introuvable' });
      const p = j.product, nom = [p.product_name_fr || p.product_name, p.brands ? p.brands.split(',')[0] : '', p.quantity].filter(Boolean).join(' ').trim();
      /* La photo est téléchargée ici puis renvoyée au navigateur, qui la réduit à quelques Ko avant de l'enregistrer. */
      let image_data = null;
      const src = p.image_front_small_url || p.image_front_url;
      if (src) {
        try {
          const ri = await fetch(src); const buf = Buffer.from(await ri.arrayBuffer());
          const type = (ri.headers.get('content-type') || 'image/jpeg').split(';')[0];
          if (ri.ok && buf.length < 400000 && /^image\/(jpeg|png|webp)$/.test(type)) image_data = 'data:' + type + ';base64,' + buf.toString('base64');
        } catch (e) { /* pas de photo */ }
      }
      res.json({ ok: true, nom: nom.slice(0, 80), image_data });
    } catch (err) { res.json({ ok: false, error: 'indisponible' }); }
  });

  async function enregistrerProduit(b, auteur) {
    const nom = String(b.nom || '').trim().slice(0, 80);
    const prix = Math.round(Number(String(b.prix_fcfa).replace(/[^\d]/g, '')));
    if (!nom) return { ok: false, error: 'nom_requis' };
    if (!Number.isFinite(prix) || prix < 0 || prix > 10000000) return { ok: false, error: 'prix_invalide' };
    const ligne = { nom, rayon: RAYONS_EPI.includes(b.rayon) ? b.rayon : 'Autre', prix_fcfa: prix, code_barres: normCodeEpi(b.code_barres) };
    if (b.rupture !== undefined) ligne.rupture = !!b.rupture;
    if (b.image !== undefined) ligne.image_url = await enregistrerImage(b.image);
    if (b.actif !== undefined) ligne.actif = !!b.actif;
    if (ligne.code_barres) {
      const { data: autre } = await db.from('epi_produits').select('id, nom').eq('code_barres', ligne.code_barres).maybeSingle();
      if (autre && autre.id !== b.id) return { ok: false, error: 'code_deja_pris', par: autre.nom };
    }
    if (b.id) {
      const { data: avant } = await db.from('epi_produits').select('prix_fcfa').eq('id', b.id).maybeSingle();
      if (!avant) return { ok: false, error: 'introuvable' };
      ligne.modifie_le = new Date().toISOString();
      await db.from('epi_produits').update(ligne).eq('id', b.id);
      if (Number(avant.prix_fcfa) !== prix) await db.from('epi_prix_historique').insert({ produit_id: b.id, ancien_fcfa: avant.prix_fcfa, nouveau_fcfa: prix, par: auteur });
      return { ok: true, id: b.id };
    }
    const { data: n, error } = await db.from('epi_produits').insert(Object.assign({ actif: true, rupture: false }, ligne)).select().single();
    if (error || !n) return { ok: false, error: 'enregistrement_impossible' };
    return { ok: true, id: n.id };
  }
  app.post('/admin/epicerie/produit', requireAdmin, async (req, res) => {
    try { if (!db) return pasDeBase(res); res.json(await enregistrerProduit(req.body || {}, 'admin')); }
    catch (err) { erreurServeur(res, 'admin epi produit', err); }
  });

  /* Import d'un fichier Excel/CSV : une ligne par produit. Si le code-barres (ou à défaut le nom) existe déjà, le prix est mis à jour. */
  app.post('/admin/epicerie/import', requireAdmin, async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      const rows = Array.isArray((req.body || {}).produits) ? req.body.produits.slice(0, 5000) : [];
      const { data: tous } = await db.from('epi_produits').select('id, nom, code_barres').limit(10000);
      const parCode = {}, parNom = {};
      (tous || []).forEach((x) => { if (x.code_barres) parCode[x.code_barres] = x.id; parNom[x.nom.trim().toLowerCase()] = x.id; });
      let crees = 0, maj = 0; const erreurs = [];
      for (let i = 0; i < rows.length; i++) {
        const r = rows[i], code = normCodeEpi(r.code_barres);
        const id = (code && parCode[code]) || parNom[String(r.nom || '').trim().toLowerCase()] || null;
        const out = await enregistrerProduit(Object.assign({}, r, { id }), 'import');
        if (!out.ok) erreurs.push({ ligne: i + 2, nom: r.nom || '', erreur: out.error });
        else if (id) maj++; else { crees++; if (code) parCode[code] = out.id; parNom[String(r.nom).trim().toLowerCase()] = out.id; }
      }
      res.json({ ok: true, crees, maj, erreurs });
    } catch (err) { erreurServeur(res, 'admin epi import', err); }
  });

  /* Ventes de l'épicerie : jour par jour et produits les plus vendus. */
  app.get('/admin/epicerie/ventes', requireAdmin, async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      const jour = /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.jour || '')) ? req.query.jour : jourParis();
      const { data: ventes } = await db.from('epi_ventes').select('id, numero, total_fcfa, created_at, operateur_id').eq('jour', jour).order('created_at', { ascending: false });
      const ids = (ventes || []).map((v) => v.id);
      const { data: lignes } = ids.length ? await db.from('epi_lignes').select('nom, quantite, total_fcfa, vente_id').in('vente_id', ids) : { data: [] };
      const top = {}; (lignes || []).forEach((l) => { const t = top[l.nom] || (top[l.nom] = { nom: l.nom, quantite: 0, total_fcfa: 0 }); t.quantite += l.quantite; t.total_fcfa += l.total_fcfa; });
      res.json({ ok: true, jour, nb_tickets: (ventes || []).length, total_fcfa: (ventes || []).reduce((t, v) => t + Number(v.total_fcfa || 0), 0),
        top: Object.values(top).sort((a, b) => b.total_fcfa - a.total_fcfa).slice(0, 10), tickets: (ventes || []).slice(0, 50) });
    } catch (err) { erreurServeur(res, 'admin epi ventes', err); }
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


  /* ── Badgeuse ─────────────────────────────────────────────────────────
     Lecteur USB 125 kHz en émulation clavier (ou douchette + badge papier BDG-…).
     Pas besoin d'être connecté : on badge en arrivant et en partant.
     Le premier passage du jour = arrivée, le suivant = départ, puis on alterne. */
  const normBadge = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9-]/g, '');
  app.post('/op/badge', async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      if (!rateLimit('op-badge:' + clientIp(req), 30, 60000)) return res.status(429).json({ ok: false, error: 'trop_de_tentatives' });
      const code = normBadge((req.body || {}).code);
      if (code.length < 4) return res.json({ ok: false, error: 'badge_inconnu' });
      const { data: op } = await db.from('operateurs').select('id, nom, identifiant, actif').eq('badge', code).maybeSingle();
      if (!op || !op.actif) { console.warn('badge inconnu', code, clientIp(req)); return res.json({ ok: false, error: 'badge_inconnu' }); }
      const jour = jourParis(), t = new Date();
      const { data: avant } = await db.from('op_badgeages').select('sens, le').eq('operateur_id', op.id).eq('jour', jour).order('le', { ascending: false }).limit(1);
      const dernier = (avant || [])[0];
      if (dernier && t - new Date(dernier.le) < 60000) return res.json({ ok: true, deja: true, nom: op.nom || op.identifiant, sens: dernier.sens, le: dernier.le });
      const sens = !dernier || dernier.sens === 'depart' ? 'arrivee' : 'depart';
      await db.from('op_badgeages').insert({ operateur_id: op.id, jour, sens, le: t.toISOString(), source: code.startsWith('BDG') ? 'papier' : 'rfid' });
      await journal(op, 'badge_' + sens, null, { ip: clientIp(req) });
      res.json({ ok: true, nom: op.nom || op.identifiant, sens, le: t.toISOString() });
    } catch (err) { erreurServeur(res, 'badge', err); }
  });

  /* Attribuer un badge à un agent : code lu sur le lecteur, ou badge papier généré. */
  app.post('/admin/operateurs/badge', requireAdmin, async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      const b = req.body || {};
      let code = b.generer ? 'BDG-' + crypto.randomBytes(4).toString('hex').toUpperCase().slice(0, 6) : normBadge(b.badge);
      if (!code) code = null;
      if (code && code.length < 4) return res.json({ ok: false, error: 'badge_invalide' });
      if (code) {
        const { data: autre } = await db.from('operateurs').select('id, nom').eq('badge', code).maybeSingle();
        if (autre && autre.id !== b.id) return res.json({ ok: false, error: 'badge_deja_pris', par: autre.nom });
      }
      await db.from('operateurs').update({ badge: code }).eq('id', b.id);
      res.json({ ok: true, badge: code });
    } catch (err) { erreurServeur(res, 'admin badge', err); }
  });


  /* Activité du jour, vue par l'administrateur (tableau de bord admin). */
  app.get('/admin/activite', requireAdmin, async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      const debut = debutJourBzv();
      const [rc, br, lv] = await Promise.all([
        db.from('recharges_operateur').select('client_id, telephone, montant_fcfa, statut').gte('created_at', debut),
        db.from('borne_depots').select('montant_fcfa').gte('depose_le', debut),
        db.from('colis').select('client_id').eq('statut', 'livre').gte('livre_at', debut),
      ]);
      const recharges = (rc.data || []).filter((x) => x.statut !== 'refuse'), borne = br.data || [], livres = lv.data || [];
      const somme = (l) => l.reduce((t, x) => t + Number(x.montant_fcfa || 0), 0);
      res.json({ ok: true,
        recharges: recharges.length, recharges_fcfa: somme(recharges),
        borne: borne.length, borne_fcfa: somme(borne), colis_livres: livres.length,
        operations: recharges.length + borne.length + livres.length });
    } catch (err) { erreurServeur(res, 'admin activite', err); }
  });

  /* Départ : l'agent se déconnecte. */
  app.post('/op/deconnexion', requireOp, async (req, res) => {
    await noterPresence(req.op, 'depart');
    await journal(req.op, 'deconnexion', null, null);
    res.json({ ok: true });
  });

  /* Croisement badge / connexion : écart de plus de 15 min, ou l'un sans l'autre. */
  function croiser(p, badge, present, fin) {
    const a = [], mn = (x, y) => Math.round((new Date(x) - new Date(y)) / 60000);
    if (!badge || !badge.arrivee) { a.push('Connecté sans badger son arrivée'); return a; }
    const ea = mn(p.arrivee, badge.arrivee);
    if (Math.abs(ea) > 15) a.push('Arrivée : ' + (ea > 0 ? 'connecté ' + ea + ' min après le badge' : 'connecté ' + (-ea) + ' min avant le badge'));
    if (!present && fin) {
      if (!badge.depart || badge.en_cours) a.push('Départ non badgé');
      else { const ed = mn(fin, badge.depart); if (Math.abs(ed) > 15) a.push('Départ : ' + (ed > 0 ? 'encore actif ' + ed + ' min après le badge' : 'parti de la page ' + (-ed) + ' min avant le badge')); }
    }
    return a;
  }

  /* Pointage vu par l'administrateur : aujourd'hui et les jours précédents. */
  app.get('/admin/presences', requireAdmin, async (req, res) => {
    try {
      if (!db) return pasDeBase(res);
      /* ?mois=2026-11 : tout le mois ; sinon les N derniers jours. */
      let depuis, jusqua = '9999-12-31';
      const mois = String(req.query.mois || '');
      if (/^\d{4}-\d{2}$/.test(mois)) {
        const [a, m] = mois.split('-').map(Number);
        depuis = mois + '-01'; jusqua = new Date(Date.UTC(a, m, 0)).toISOString().slice(0, 10);
      } else {
        const n = Math.min(Math.max(parseInt(req.query.jours, 10) || 14, 1), 62);
        depuis = new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);
      }
      const [{ data: pres }, { data: ops }, { data: clos }, { data: bdg }] = await Promise.all([
        db.from('op_presences').select('*').gte('jour', depuis).lte('jour', jusqua).order('jour', { ascending: false }),
        db.from('operateurs').select('id, nom, identifiant, actif'),
        db.from('caisse_clotures').select('operateur_id, jour, created_at').gte('jour', depuis).lte('jour', jusqua),
        db.from('op_badgeages').select('operateur_id, jour, sens, le').gte('jour', depuis).lte('jour', jusqua),
      ]);
      /* Badges du jour : première arrivée, dernier départ, temps entre chaque paire arrivée/départ. */
      const B = {};
      (bdg || []).slice().sort((a, b) => (a.le < b.le ? -1 : 1)).forEach((x) => {
        const k = x.operateur_id + ':' + x.jour, o = B[k] || (B[k] = { arrivee: null, depart: null, minutes: 0, ouvert: null, nb: 0 });
        o.nb++;
        if (x.sens === 'arrivee') { if (!o.arrivee) o.arrivee = x.le; o.ouvert = x.le; }
        else { o.depart = x.le; if (o.ouvert) { o.minutes += Math.round((new Date(x.le) - new Date(o.ouvert)) / 60000); o.ouvert = null; } }
      });
      const nom = {}; (ops || []).forEach((o) => { nom[o.id] = o.nom || o.identifiant; });
      const cloA = {}; (clos || []).forEach((c) => { cloA[c.operateur_id + ':' + c.jour] = c.created_at; });
      const aujourdhui = jourParis(), t = Date.now();
      /* Un jour badgé sans aucune connexion apparaît aussi. */
      const presT = (pres || []).slice();
      const vus = new Set(presT.map((p) => p.operateur_id + ':' + p.jour));
      Object.keys(B).forEach((k) => { if (!vus.has(k)) { const i = k.lastIndexOf(':'); presT.push({ operateur_id: k.slice(0, i), jour: k.slice(i + 1), sans_connexion: true }); } });
      const ECART_MAX = 15;
      const lignes = presT.map((p) => {
        const b = B[p.operateur_id + ':' + p.jour] || null;
        const badge = b ? { arrivee: b.arrivee, depart: b.depart, minutes: b.minutes + (b.ouvert && p.jour === aujourdhui ? Math.round((t - new Date(b.ouvert)) / 60000) : 0), en_cours: !!b.ouvert } : null;
        if (p.sans_connexion) {
          return { operateur_id: p.operateur_id, operateur: nom[p.operateur_id] || '?', jour: p.jour, arrivee: null, depart: null, present: false, duree_min: null, nb_connexions: 0,
            cloture_le: cloA[p.operateur_id + ':' + p.jour] || null, badge, alertes: ['Badgé sans connexion à la page'] };
        }
        const present = p.jour === aujourdhui && !p.depart && t - new Date(p.derniere_activite).getTime() < PRESENT_SI_MS;
        const fin = present ? null : (p.depart || p.derniere_activite);
        return {
          operateur_id: p.operateur_id, operateur: nom[p.operateur_id] || '?', jour: p.jour,
          arrivee: p.arrivee, depart: fin, depart_note: !!p.depart, present,
          duree_min: Math.round(((fin ? new Date(fin).getTime() : t) - new Date(p.arrivee).getTime()) / 60000),
          nb_connexions: p.nb_connexions || 0, cloture_le: cloA[p.operateur_id + ':' + p.jour] || null,
          badge, alertes: croiser(p, badge, present, fin),
        };
      }).sort((a, b) => (a.jour < b.jour ? 1 : a.jour > b.jour ? -1 : a.operateur.localeCompare(b.operateur)));
      const auj = (ops || []).filter((o) => o.actif).map((o) => lignes.find((l) => l.jour === aujourdhui && l.operateur_id === o.id) || { operateur_id: o.id, operateur: nom[o.id], jour: aujourdhui, absent: true });
      const totaux = {};
      lignes.forEach((l) => {
        const t0 = totaux[l.operateur_id] || (totaux[l.operateur_id] = { operateur: l.operateur, jours: 0, minutes: 0, minutes_badge: 0, alertes: 0 });
        t0.jours++; t0.minutes += Math.max(0, l.duree_min || 0); t0.minutes_badge += l.badge ? Math.max(0, l.badge.minutes) : 0; t0.alertes += l.alertes.length ? 1 : 0;
      });
      res.json({ ok: true, du: depuis, au: jusqua, aujourdhui: auj, lignes, totaux: Object.values(totaux).sort((a, b) => a.operateur.localeCompare(b.operateur)) });
    } catch (err) { erreurServeur(res, 'presences', err); }
  });

  app.get('/admin/operateurs', requireAdmin, async (req, res) => {
    try {
      const { data } = await db.from('operateurs').select('id, identifiant, nom, agence, actif, active_le, derniere_connexion, activation_expire, created_at, badge').order('created_at', { ascending: true });
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
      /* Envoi par WhatsApp d'abord (modèle approuvé TWILIO_WA_RECHARGE_SID, 3 variables : montant, code, n° de reçu),
         sinon par SMS. */
      let smsOk = false, smsErreur = null, canal = null;
      if (process.env.TWILIO_WHATSAPP_FROM && process.env.TWILIO_WA_RECHARGE_SID) {
        try {
          await twilio.messages.create({
            from: 'whatsapp:' + process.env.TWILIO_WHATSAPP_FROM, to: 'whatsapp:' + dem.telephone,
            contentSid: process.env.TWILIO_WA_RECHARGE_SID,
            contentVariables: JSON.stringify({ '1': montantTxt, '2': code, '3': dem.numero }),
          });
          smsOk = true; canal = 'whatsapp';
        } catch (e) { smsErreur = 'WhatsApp : ' + e.message; console.error('whatsapp recharge op:', e.message); }
      }
      if (!smsOk && process.env.TWILIO_SMS_FROM) {
        try { await twilio.messages.create({ from: process.env.TWILIO_SMS_FROM, to: dem.telephone, body: texte }); smsOk = true; canal = 'sms'; }
        catch (e) { smsErreur = (smsErreur ? smsErreur + ' ; ' : '') + 'SMS : ' + e.message; console.error('sms recharge op:', e.message); }
      } else if (!smsOk && !smsErreur) smsErreur = 'ni WhatsApp ni SMS configurés';
      await db.from('recharges_operateur').update({ statut: 'envoye', code, envoye_le: now(), sms_ok: smsOk }).eq('id', id);
      res.json({ ok: true, code, sms_ok: smsOk, canal, sms_erreur: smsErreur, texte, telephone: dem.telephone });
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


  /* ── Application « Colispo PDA » (installable depuis Chrome sur le PDA) ──
     La page tiinda.com/pages/pda pointe vers ce fichier de description : Chrome propose alors
     « Installer l'application », avec une icône sur l'écran d'accueil et l'ouverture en plein écran. */
  const ICONES_PDA = {
    '192': Buffer.from('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', 'base64'),
    '512': Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAIAAAB7GkOtAAAxsElEQVR42u3dZ2BUVd7H8Ts1ZTItjRISYK1gXcXGoo+7dlBAUUQRCIFQAqRTLWtDajo9lACCiCBiwbq7uva+KCIiNQmE1GmZlMmU54WFJIQQkslkZu7382o3xGTyP3fOb865554jOaLrJgAAxEdKCQCAAAAAEAAAAAIAAEAAAAAIAAAAAQAAIAAAAAQAAIAAAAAQAAAAAgAAQAAAAAgAAAABAAAgAAAABAAAgAAAABAAAAACAABAAAAACAAAAAEAACAAAIAAAAAQAAAAAgAAQAAAAAgAAAABAAAgAAAABAAAgAAAABAAAAACAABAAAAACAAAAAEAACAAAAAEAACAAAAAEAAAAAIAAEAAAAAIAAAAAQAAIAAAgAAAABAAAAACAABAAAAACAAAAAEAACAAAAAEAACAAAAAEAAAAAIAAEAAAAAIAAAAAQAAIAAAAAQAAIAAAAAQAAAAAgAAQAAAAAgAAAABAAAgAAAABAAAEAAAAAIAAEAAAAAIAAAAAQAAIAAAAAQAAIAAAAAQAAAAAgAAQAAAAAgAAAABAAAgAAAABAAAgAAAABAAAAACAABAAAAACAAAAAEAACAAAAAEAAAQAAAAAgAAQAAAAAgAAAABAAAgAAAABAAAgAAAABAAAAACAABAAAAACAAAAAEAACAAAAAEAACAAAAAEAAAAAIAAEAAAAAIAAAAAQAAIAAAAAQAAIAAAADRklMCiI3ysn6q+4cH/e0mRf9LBUFo2H+g9uNPrbtft/30M8WBqEiO6LpRBYiEov+loY/PCR58d4v/WrPnnar5Cxv2H6BQIAAAP+r6L7lYP2+W6r4hgkTS2ve5XNY33jK8sLjhl4MUDQQA4ONd/4UX6OfNUg0feo6uv1kM7NptWLCk4dBhCggCAPA98r599HNnhYwYLkjbtdjB6azescuwcIn96DGKCQIA8JGuPyZGPyc9ZOQIQSbr6M9yOKq37zAszLAXFlJYEACA95L1itLPTlOPGinI3brCzW63vPSyYXGmo/gERQYBAHhZ19+ju35Wmjp2TKf+FkvBZsPiDEfJKQoOAgDwgq6/W6QuPUUzdrSgVHri99ls5k1bjEuzHKVlFB8EANA1pOHh+rQk9fixkoAAD/9qV12dpWCzISPHWVFBQ4AAADzY9YeG6lITNXHjJEFBXfgyXLW15vUbjZm5zqoqGgUEANDJXb9Op0ueromPkwQHe8lLctXWmvPXG7PynEYjDQQCAOiErl+r0c6Ypp08URKi8sKX56q2mlavNeUtd5rMNBYIAMB9XX/CFO2UeIlG7eUv1WW2mFauMS5f6bJU03AgAIAOXKDqEO3USdqEyVKt1odettNkMq1YbVq+ymWtoRFBAADneWmqgrWT47XTp0j1eh/9E5wGgzF3hXn1WldtLQ0KAgBow0UZFKSJj9MlJkjDwvzgz3FWVhqzl5nXFRADIACAs1+OgYGauHHa5BmyiHA/+9Mc5RWmrFzzhk2uujoaGgQA0IhSqRk/VpeSKOsW6cd/peNUqTE7z7xhk2Cz0eYgACB6CoVm7GhdapKsZw+R/MWOkyXGzBzzpi1CQwPtDwIAoiSXq0eP0qenyHpFifCvtxcVGzOyLVu2CXY71wIIAIiGTKYeNVI3K0UeEyPyStiPFxqXZFm2bRccDq4LEADwa1JpyMgR+llp8r59KMbpGDh6zLA4o3r7TsHppBogAOB/15ok5MH7dbPSFBdeQDFa1HDosGHRUuvO1wSXi2qAAICfUN0/TD87TXHJxZTi3DHwy0HDwqXW116nFCAA4NuC77oj9J+PK/pdSinOLwZ+PlD1zPyad9+nFCAAIPjind6whc9rJo6nEkIHTqCsmP04Dw2AAICP6bF7R+Atg6hDB9n2/XTy9sGu+npKAbeTUgJ0htDnn6b3dwvl5ZdpEyZTBzACgG+Q9ewR89P31MFdnGZzYb+rXTXsLA1GAPB6IQ+NoAjufJdqNOrRo6gDCAD4gICrrqAIbi7pgGspAggA+AD/28y560vq15ukggCA4Edz1haK4F6OsnKKAAIAPqDu088pgnvZ9v5AEUAAwAeYCzY7DQbq4DYuV/Wu3ZQBBAB8ob+qqTEsWEId3MWyYZPjZAl1gMBzAPCGQ9sDb7hO0e8SQRAa9h+o++qbFo87D89eqh73GOXqIPux48U33nLmk8BtbAWgFXJKgLZTXnG5flZq8L2Dm3295s09VQsWN+w/0PiLFcnp9uJi/eNzqFu71bz7fvn0lGa9/3m1AsAIAB2l6H9p6NxZZ3Y6QqN56pq33q56fmHDLwcbfzn47jtDn36CjaCF898Uuuq5BTVvve2WVgAIALSr67/kYv3cmaqh9woSidCG25XW3W8Y5i9qOHRY4DwA950H4JZWAAgAtLnrv/AC/Zx01f3DBOl5LhZwOq2v7jYsWtqkA+JEsHadCObmVgAIALRO3rePfnZ6yEMPnHen05jDUf3Kq4bFGfajxwTOBBbO+0zgTmwFgABAC11/TIx+dmrIww8JMpl7fqLDYdm23bg4y15YKDQ6K0Y9aqRuVoo8JkbsXf/xQuOSLMu27YLD4elWAAFAAOD3PrlXlH5mqvrRhwV5J6wNa2iwbH3ZsDTLUXyiUdrI1aNH6dNTZL2ixNj1FxUbM7ItW7YJdntXtgIIAIi66+/RXZ+eon7sEUGp7NzfZLOZN281ZmQ7Sk6d/qJCoRk7WpeaJOvZQyQFd5wsMWbmmDdtERoavKUVQABAhHtM6lKT1OMekwQEeOyXuurrLRtfNGbmOErLTn9VqdSMH6tLSfTvbS8dp0qN2XnmDZsaH/PrRa0AAgBiIA0P16UmasaPlQQGdskLcNXVmTdsMmbmOisqTl+OgYGauHHa5Bn+t6G0o7zClJVr3rDJVVfn5a0AAgD+2/WHhuqSp2smxEqCgwUv2DXIvK7AmL3MWVXVeJMDTXycLjFBGhbmBwV3VlYac5ab125ovFWD97cCCAD4V9ev02kTE7STJkpUwV71wlzWGtOatabcFU6j8fSlqQrWTo7XTp8i1et9tes3GIy5K8yr1zbp+n2qFUAAwPe7fq1GOz1BO3miRB3itS/SZak2rco3LV/pNJlPX6DqEO3kidrpU6VarS91/SaTadlK08o1LmuNH7QCCAD4ZgOrQ3TTpmgTpnhzp9OsAzIuX2lasdplqW7SdSZM0U6Jl2jU3v76zRbTyjXG5Ssbv37/aAUQAPCdplUFa6dO0k6bItXpfG/yxGg0LVtpWpXf/BN04jTtpImSEJU3dprVVtPqtaa85U1GMH7XCiAA4O379WunTtJOmywNDfXpP8RZVWXMWW7OX99sDl2XPF0TH+cNt09/7/pra835641ZeU3uYfh1K4AAgPc1Z2CgZuJ4XdI0abj/LKN0VlQYs5eZ1xU0WUAZGqpLTdTEjZMEBXVx179+ozEzt8kqJtG0AggAeAelUjNhnC45URYZ4Zd/n6O0zJidZ16/sfEjVNLwcH1aknr8WE8+QvXnCnpLwWZDRk6TFfSibAUQAOg6CoUmdowuJVHWo7vf/62OklPGrFxzweYmmyh0i9Slp2jGju70TRSEP7ZS2LTFuDSryTO0om8FEADwLLlcPeZRfVqyLKqnqP5uR/EJQ2aOZfPWJtuo9eiun5Wmjh3Tqb/aUrDZsCSzyRHttEKjVgABgM4nk6kfHaWbmSyPjhZtDexFRcYl2Zat2xpvpCzrFaWfnaYeNdLNu2na7ZaXXjYszmyyjyatcJZWAAGAziGVhox6SD8zVd6nN8UQBMF+7LhhSWb1tleaHKUSE6Ofkx4ycoQb9tN3OKq37zAszGiykz6t0IZWAAEAN7aV5PeztP7Sl2I003D4iHFxRvUrrzY+TFHet49+7qyQEcPbeaKW01m9Y5dh4ZImZ2nRCufZCiAA0FGqEffrZ6cpLrqQUrTWAR381bAow/rqa0Kzk43nzVINH9qm49SFPw5V37XbsGBJ86PtaYX2tgIIALSr6x92n352mqLfpZSirR3QzwcMC5daX3+zSQxccrH+8dmqewefIwZcLusbbxleWNzwy0Fawe2tAAIAQtuP5+22MV959VWUoh1s/9tbOmGK/cjRJjHQ/9LQx+cED767xf+kZs87VfMXNuw/QCt0aiuAAMA5BN32927r13j/3mfezFVtLU9Mte7a3ezryisu006bGvLwg39+xbpzlzFnme3Hn2gFj7UCCAC0TNH/0qh/v+v5p1v90onb7rZ99z9awUdbAZ1KSgm8UPeXNtHvuEvok/NoBd9tBRAA4hJw4/XymBjq4C5Bt94ScP0AWsEXWwEEgOgE33k7RXCvwIE30Qq+2AogAERH3qMHRXAvRUw0reCLrQACQHQc5eUUwc2ZGt2LVvDFVgABIL4AqKikCO5lLymhFXyxFUAAiE7d519QBPeyvrqbVvDFVgABIDr1X39bs+dd6uDG/YprP/wvreCLrQACQIwqn3rGxe7q7uByucriJtMKvtsKIADE93Hp8JHSR8e5LNWUooMMTzxd/813zb6ovKyf/om5Pd9+vffxg72PH+z59uv6ebOVl/WjFTzZChDYCgKCICguvECq09qLipucMSsI8j69uxXkK6+6khK1g23fT+XTU2x7f+joZnC0grtbQRoWKo+McJjMTU7WBAEgiOu5mBtDn/tnwDV//fMrjpMlls1bTPkbnJWVbEQsuH076HmzVPcNYTvormoFqVajGj4s+O47pGFhvxe7vr7mrbet23c4qgxUjAAQxHOso35Wmm5mSosnVTlNJsPzC83rChofq8RRJBwI49OtoBp6r3r8WIlK1eJ/Yl6+yrr7DUpHAIiCft5s3cyUc42d95dPS7L98COHEXIkpE+3guLii3RpSfK+5yiXOXeZ9c23qSEB4OeUl/eP+uiDNnVJLpdl44tVTz/nNJk5jlzgUHhfawWpSqWJjws6yx2XM1XNnlf//V6KSQD4s4jl2SGPjjqPj6GVlVVPz7e8uLXJV2Uy9aOjdDOT5dHRYl5ablySbdm6TWi0WFPWK0o/O009aqQgl7v1l9ktL71sWJzpKD5BK5yzFQRBCL7nLvWEWKlG0/YfZdv7Q+XMuXQRBIA/6/XNZ4oL/nK+/1X9t99VJKXZfvq5yVflcvWYR/VpybKonqKqoePESUNGtmXzVsFuP90b9+iun5Wmjh3Tqb/aUrDZsDjDUXKKVmixFQRBkPfpo0tLVFxySTt+Zsm99ws2G70EAeCfpHp97yM/t3suwpy/vur5BS5rTZOvKxSa2DG6lERZj+7+3+mUnDJm5ZoLNgsNDae7/m6RuvQUzdjRglLpiRdhs5k3bTEuzWqybFf0rSAIgjQ4WB07RjX0Xpe0nQ8YlcdNsjceY4EA8CeBN93QY0+HdkRxlJVXPfVM9cs7mv+DUqmZME6XnCiLjPDPTqe0zJiTZ163sfEnRGl4uD4tST1+rOeP7nLV1VkKNhsycpwVFSJvhd8E3/4PTXycRK/vyM+vTElvPswFAeA3Aq67tud7b3X859R9+nlFcnqzRYqCIEgCAzUTx+uSpknDw/2maM6KCmP2MvO6Aldd3emuPzRUl5qoiRsnCQrqwtfmqq01r99ozMx1VlWJsBV+I4+K0qYmKq+4vOO/pTIp1fbzL3QUBIB/Ul51ZdSH77nnZzU0mFasNizKcNXWNm/UoCDNpAm6xARpaKhvdzpVVcbsZea1Gxr/jVKdTpc8XRMfJwkO9pLX6aqtNeevN2blOY1GkbTC739jQIB67GjVA8MEmXtuuVckJJ75sQYEgJ9Q9L+016cfunNIXnyiYu6TNW/uaaFpVcHaqZO006ZIdTrf63SMRtOylaZV+Y1veEi1Gu2MadrJEyUhKi98za5qq2n1WlPe8sbLdv2vFf4UOOhvmoRJMreOcsrjp9qPF9JREAB+GgAX/KXXN5+5/cfW/feT8hkp9sKiFhpYHaJNmKybNlWiDvGJErks1ca85aZV+Y13YZNqNdqEKdop8RKN2ttfv9liWrnGuHxl49fvH63wJ3n37trUROXVV7n995aNj3ecOElHQQD4J3lMdPTerzvlHVtfb8rOM2TmtriKTqrVaKcnaCdP9OYOyGWpNq3KNy1f2eQTtDpEO3WSNmGyVKv1pc/OJpNpxWrT8lXNRzC+2Qqnm0OhCHlkZMjDDwkKRWf89rLHxjvKyugoCAD/JOsWGXPgh877+fbjhRXpc2o/+HeL/yrV6bSJCdpJEyWqYK8qi8taY1qz1pS7oskcuipYOzleO32KtGMLS7oyBgwGY+4K8+q1ze5h+FArCE2XMGhnJMi6d+I619KRo8/220EACKJ+DqDNat56u2L242cbSktDQ3XJ0zUTYr3hJqqrpsa8rsCYvazJKpqgIE18nC4x4c9tI32as7Ly9/UzjWPA61uhyQeXiHDNtKmBA2/s7FdyasTDHMBAAPhvuUNUfYoOe+YtbViSZcpbIZzlTCtpeLguNVEzfqwkMLBrOp26OvOGTcbM3Mbr6CWBgZq4cdrkGbKIcD9rekd5hSkr17xhU5PFrF7ZCk2uWLk85MEHVKNHeeZJi1NDH3DV1dNREAB+SqnsW+q5RQ4Nvx6qSE6v++yLVqakdKlJ6nGPefJBKld9vWXji8bMnCZP0iqVmvFjdSmJsm6Rftz+jlOlxuw884ZNjW/VeFErNN+48DLdzBRZjx4ee1Wn7hnKMZwEgD/razjl4d9o3bGr8vGnHGXlZ42BHt316SnquHEeeDHmdQXGjOwme+koFJqxo3WpSbKePURyDThOlhgzc8ybtjTZ0KJrW6HZJaHXa6bGB976fx6uTMmdQ+giCAC/DoCyok5aQdH62sSqhYvNq9c13q23+Xu+V5R+Zqr60YfdvI/mH4+tWba+bFia1WQ3TblcPXqUPj1F1itKEOM+msXGjGzLlm1NtrTzfCsIzU8rUg0fqhn3mOD5R6wbGkqGDKeLIAD8WZ/iI121/KPhwC/l05Lrv/teaG2haox+dmrIww+5YSf9P/aws2zbblyc1WQ/fZlMPWqkblaKPCZG5NeD/XihcUmWZdv2xndrPNQKZ1D2u1SbmiTv3UWNUltbMuxBuggCwJ/1Pry/a/cGqN66rfLJZ8+23uP0WVqz00MeekBo77aOvx+l8sqrhsUZTU7Ukkp/P1Grbx8uhtMxcPSYYXFG9fadTY616bxWOPNzv0ajmTQh6M7bu7AILpPp1EOPcjEQAP4s5ue9su7duvwR/6pn5lsKNrf+bYoLL9DPSVfdP+y8OyCn0/rqbsOipU32dZFIQh68XzcrTXHhBVwGLQ/RDh02LFpq3flakyMV3dsKLQm+d7AmbpwkJKTL18uWPjKWy4AA8GfRP3ztJQdI2fb+UJ6Y1uTY4RZj4JKL9XNnqobe26ZD1V0u6+43DPMXNT9O/f5h+tlpiksu5gI4dwz8ctCwcKn1tdfd3got7k2iS0uSX+gVx9w7S0tLx8RxARAAAieCeeo95zSv31j17PxzPn2j6H9p6NxZwfcObqXTqXnr7arnFzb8crDJp8u77gj95+OKfpfS9OcXAz8fqHpmfs2777ulFc4kVanUE2KDh9wtSKRe8ic7iovL4ibT9ASAXwfAZx96W2/oKK+o+uez1S9tP+d3Kq+4XD9nZvDgu5p9vWbPu4aFS2w/7hOaHlwctvB5zcTxNLrQgRMoK2Y/3mx/p/NrhZYE3Xm7Nj5O4mXbK9mPHiufPI1GJwD8WdRH7yuvvMILX1j9l1+XJ6Wd85OjIAjyvn1CRgyXyOWCILjs9uqdr7V4g7HH7h2BtwyixTvItu+nk7cPdtXXt68VztyOUJeapOjfzxsHPQd/rZieTIsTAP6s53tvBVx3rZe+OLvdtHqtYcHiFvd/Py+hzz+tnTaF5nYLw7MvGLNyO/pWDwxUx44JGT7UJZV655/ZsP/niuR0mtuTpJTAw1wtbdfsLeRy7bQp0V9/prp/WEd+jKxnD3p/N9ImT+/gnnGBt94SWZCvemC41/b+vz0IRlsTAP4eAF5/lct6dI9cv7rH7h3yPr3b9xNCHhpBQ7vzXarRqEePamemR0WFZSzSz5vt/SdTOgkAAsD/A6DeNzY7DLxlUPSXH+ufmNuOHcoCrrqChnavgAHnPW0oUSg0cbER+Svccly74JEZSBqaAPB3PvQxR6nUpSX1+urj4HvuPL8xhN9t5uwNRwmdX34PvDFywxrVqIc6ZU8hsQ6O/Y+cEnAP4FzrRmK6bd1U+6//lCeltfG8VqfZQkO7VyubuTaPishIbfL0dowYvOCzESMARgD+HwA++TEn6La/R3/9qS49uS1bmdZ9+jkNLbj7sW2hDXM+6sceiVy/2id7f0FwMQVEADAC8FqSoCD943Oiv/w48OZzrO43F2x2Ggy0tfsuGlf1rt3COe67XBm5fnXI2McEpZL1ESAACIBOIe/bp8frOyIL8lvZ0s5VU2NYsIS2dhfLhk2OkyVnfQ+HhYY+9XjokgXSbt24PQYCgI85nU417L7orz/TTp96tg3rzfnrLRtfpLk7zn7seOW8p852eEvIyBGRG/IDBg3krQECwBfU1/vNAfehz/2z1+cfBVw/oMVvqEhON8xfSIN3RM2775+4Y0iLS4eVl18WuXalemJcVx0ozz0AAgBiuQl8NoqLLuz57psRK/OkYWFn/qtxaXbpI2Pbsr8QhDM2hS59bHzpqDHOiormb1qtRj8nPSxzsaxXL/8a7BAABID/TwHZ/O+PChn1UPR3n2vi487crb7mnfeKb7ylbPykhgO/0PptPLmzLDa++MZbat56+4xhl0Q1fGjkxnWB//g7n41AAPjik8A2f92uIGzxC1H//VfANX8981+tr71ePPDWsolTG349xDXQynaYZROmFN/0f9bdb7Qw2Lr4oohVeZqEyR3cF4gpIBAA3OnqFMrL+/f8YE949lKpVtPCMVU7dxXfcHP55GkNh49wJTTp+g8fKZ88rfjGW6yvvtbCu1St1qUmhi/Lkvfty0PyIABYBurFJBL1uMeiv/tC/dijLS9p376z+PpB5dOS7MeOcz3Yjx4rT0gsvn5Q9fadjY8C/lPw4LsjC/KD7r5LECR8NgIB4OPqbaK4sEJDw/Mye36wR3lZvxaPoqze+nLRgIEVM1LthYUi7fqPF1ZMTym67m/VL20XnM4zv0Hep0/Eihxt8gyJWi2OijAFRABwE9iPBFx7TdRHH4QteE6iDmnhnx0Oy4tbi64dWJGcbi8qFlHXX1RUkZRWNGCgZctLgsPRwtsyOFg7fWrE6jwvOa5dYDtoAgAsdWgPmUwzJT76689CHnrgbJ/7LBtfLLr2poq02W3cbM53OU6crEidVXTNTZZNW872gTf49n9EblgTPPRe7zmunREAAQB3BUC9IMrdjCPWrOjx5i7FhRcIZ7kBaFm/sfCvN1TOmucoOeWHXX/JqcqZcwv/eoNlw6az9XTymOjw7KXaWWkSvV6M7w2WgRIAjAD8WODfbur12YehTz8hCQo6WwyY89cX9r+6ct6TjtIyP+n6S8sq5zxR2P9q89oNZ1voIgkI0EyaELl6uXce184yUAIArAJyB4VCmzQ9+qtPVPcNaeW7zCvzi66+vuqJpx3lFT7c9ZdXVM17qujq682r17bybUG3DIosyFc9+IDrLBsriSYAGAEQAASACMh6RUVuWtdj9w55TPRZC1VXZ1q+quiq66qefMZZWelbf6CzsrLqyWeKrhxgWrnGVVd3tm+Td+8etvgF3RNzW9xIQ+CwPBAAAhOdfirwlkG9vvpEP2dmK1vYu2prTctWFl51neHZF3zijAFnVVXVM/MLrxhgWrayla5folCox42JWL9aefVVXAl/LJBjCogAYBmomEgCAnSz06K//iToH7e2VjRrjTErt/CKaw3zFzpNJi/t+o1Gw/MLCq8cYMrOc9XWCq2tjv1rZEF+yOhRPnRgLw+C+ecb8IiuG1XwJMXFF/X68mPqcKaat96umP34OVeCStQhumlTNFMnSTUab+n6zWbT8lWmlWtclurWv1MWEa6dkRBw4w0095nKxsf7/TpgAkDs5H16R3//JXU461FiS7JMeStafDyq2ZbI2mlTtVPiW37EzGMv2GwxrVxjXL7ynF2/RC5XjRyhfvRhQRlAQ7ccAI+Nd5SVUQcCwJ/JonrG7PuOOrSi4ddDFcnpdZ99cc7vlOp02hlTtZMmSkJUnu76LdWm1WtNy1Y4TeZzfnPAVVdqUxNlPXrQuK0FwMOPOThKmgDwb9Lw8N6/7qMO52Tduaty3lOOsvK27DukS0zQTIyTqDyxT7LLWmNas9aUu8JpNJ77tYWFaqdMCvy/m2nQczo14uFzDqRAAPh4AGg1vY9xQlZbP2VXLVhkXr2uxb3SWoiB1ETNhNjOOyLRVVdnXrPOmLPcWVXVhpaWqh4YphkzWjjbU29oFgBDH3DV1VMHAsCvKx4U1OfkUeognM8JWeXTkuu/+76NAyx9WpI6dox7Y8BVW2tev9GYvezMAxpbpOx3qTY1Sd47huY7jwC4Z6jrXPd+QAD4+hBA2reSpQ7n2wG7LFu3VT35bBsfBZB1i9SlJqnHPSYJCOj4p35LwWZDRk4bu36pVqOZNDHojttotPNVcucQikAA+L++hlMUQWjXQvuqZ1+wbNjUxu+X9eiuS0vWjHm0lQfNWj28s96yaYsxI7utuxJJJKr7hqjHj5GoQmisdjwGXDJkOGUgAPxfn5NHJcwLt5dt3/6KpLQ2zgj9tu1E6NyZIQ8/JLR9px2Hw7Jtu2HhUkfxCaHNj3fo0pL8/MjGzj0ru/7UfQ9QBwLA//U+ftB7HmLy1RmhzVurnn6+7ZtDyPv2CZ03W/XAMEHa6tPvTqf11d1VLyyyHz3Wxp8sVas18eOD7r7T749s7OS1VdWn7n+YOghsBSGCDzvsBtHhY4fHjo7+9jN17BihzUfvlsVPLR54a82be872PTVv7ikeeGtZ/NS29/6qe++J3LhWDAf2skcWIwC4R8y+72RRPamDe/qNvT+UJ6bZfvix7f+J8orLtNOmhjz8oNDomQNjdp5t3/62/xDFBX/RpSWJ6sjGTuUsLy8dHUsdCAD/F/39l/I+vamD+zoPp2XTlqqnn2vLQ7luGDWr1ZoJsUGD+dQvuPXEtJKycROpg8AUkCCC+10Uwb0ra9WxY6K/+0I9ZnRn/6rgwXdHFuQHDb6b3p+T8ggAsO2t11zKoaHhuRk9P9ijvPKKzvj5igv+ErEiR5s8Q6JWU22BE+EJAHAomLcJuPaaqP+8G7Z0oVTrtnVWUpVKmzQ9fEUOM/6cB0kAgFVA3j4jpJkQG/3NZ+rRj3T8hwXfc1fExrXBQ+4RJLxZGBYTABA4+9Q3dl0NX5bV84M9ysv6Ce2d8wnPy9SmJPLQhkfeFEwBEQBMAUFw94zQRx+ELZp/XufGSFUq7YyE8BU5iksuoYYC9wAIABAAvkom00yaEP3tFyGPjGzLtwffdUdkQX7wfUOY8/EkJ8NiAoAAQGelQER4xIrc7i+/2MqhMZKAgNAXntWmJUu0WiomMAVEAICbwP4k6M7be77zRovnR0pVqvC8rIAB11IlPhURAOjUBQ9c611Gefll3TauO/Pr+mee5PHsruRgBEAACOx7hc4fB/zjVkX/Sxt/RXHRhZ30+Bja/KmIACAAxMHJVhBdTXVfk8OnAv92EzXhOQACAALPAYiB4i9/afx/5VFR1ERgGSgBAE982KljBNDF5N2bbIIr07HshxEAAQDPXOvc7+pqksDAJv+/XYcGw617AfGmIABYBgrPBEBAkx5folBQE4F5UQIAnsCS5y4PAEXTj/wKOTURuAdAAIBnXkShaY8vkREAvCkIAHD4kVjuAQQ0+b9KpoC6/B6AgyIQADwJjC6ZAiIABKaACAAwAhBHADT9yC+RMwXEMlACABwKL5YACGAEQACAAOBaZwQgSFgFxHMABAAEloGKRLMnv1gFJHAeAAEAVryJxx/TPjwFxrCYAAABIIh0Fog7wEwBEQBgFZA4V4KyBEhgKwgCAIwARLodEE+BEQAEAAgAkU0BMQLwIk6mgAgAPuxA8PxNYDkjAIEngQkA8CCYqKaAAngKjBtjBAC41sV5E1jBU2CMAAgAsBmcqJeBcg/AO5aB8qmIAOBEMDAFxLAYBACjXTAFJCJOJzUgAAS2A4Lg2e2AWAUksC6OAACzQOJ8DoApIDYCIgDAfWCxPgjGFJDApCgBAG55sQoIjAAIAHR+APAsGFNAIAAIAEYAYApIYAoIBIB4EABeswxUYBVQ148ACAACgCkgeNIfD4JJmQJiCogAAFNAIj0RjCkggSkgAgAsAxXliWAcCSnwIBgBAB4EE+eJYBwK3+WcBAABwKFg6Jq9gBgBCEwBEQDgrhfPAYAAIADQ6ZgC6nJMAbEmggCgBNwEFvlNYKaAvOA0GEYABAAfecAyUI4DAwHAufDo/AAIYApI4MF4AgDcBBb1CIApIKaACACwDFSsm8ExAiAACABwJCQBAIEngQkAcBPY7zEF5EUBwAiAAGAKCJwHIEpOVgERAAQAmAJiCggEAAEAD24FwRQQB8IQAOAegEg3g2MEwCogAgA8CCYu7AYqMAVEAIArXpwjgMAAdgNlCogAAJvBcR4AuhSrgAgATgSDRwMgKOj3//Xn3WCwMwoBAO4BAHweEgMGv13DUVZOEbzgWOAAiuAVbweDgSIQACJiLyqmCIIXHAomcTgoQ9cHwImTFEFgCkhEY966OuuOXdSh6w8FU3ADoIvVvv8vikAAiE7VC4tctbXUoWuPBJDIZdShK9nqLZtepAwEgOjYjx6rSEqjDl28GwQPAXQp45IsR2kZdSAAxKj6lVdLR41xWWsoRVcFgJQA6CKumpqquU/UfvQxpSAAxKvm3feLbhhUs+cdStE1p0ISAF2h7rPPy+On1n/7PaUQWAUkiH4JROno2KB/3BqetVgeE0NBPEehFBxOyuBJztJSY3YeXT8jADRR++8Pi64bZFyUwTNiHnwOQMk+EIIH97+q3ry1LG4yvT8BAKHFg4INC5cUXz+o7r+fUAzPLAPlODDPqP/m27Lxkyybt7Drg8AUEFphLywqGfZg8L2Dwxc8J+sVRUE69R6Ay8Y9gM7lLCszrVxT9+nnlIIRANqq5s09RdcPMmXnsXE0U0C+ymG3bnulbMIUen8CAOfNVVtb9cz84oG38v7pzCkgRgCdwvbjvvKJCeb1BdzTIgDQfg2HDpfce3/ZxKmOU6VUw82UCgLA7ZxVVcYFiyvTZttPnKAaBADcwLpzV9GAm0wr1whsXubOewABnAjvzno6HNZXXyuLja/9z0dUgwCAO7msNVXznir+29/rv/yaarjtQTACwF1D1f0/l02eZl6V76qroxoEADrnbfbLwZN331c+LclZUUE13LAVhJIpoA5/NDGZjEuzKpLT7YVFVIMAQKer3vpy0YCB5nUFgpMHWTt2LDAjgA71/c6aN94qi42vfe8DikEAwHOcJnNl+pwTf7/LtvcHqtH+E8HkjADayX7oUEVCkilvhdNqpRoEALqA7YcfT9x6Z0XKTKfRSDXacx4Aq4Da8bnfYjHnLCtPSGo4fIRqEADoYpaCzUXX3GTZ8pLgclGN86BQsBXEee/i/M57ZbHx1rfephYEALyF02ComJ5y8vbBtn37qcb5TAERAEKbjzA6WjE9xZSZ47RYqAYBAK9T/933J265rXLuky4zb9E23QRmCqiNh7eYV6wunzKj4eCvVIMAgDe/WV3mVflF1w2sfuVVinHOZaBMAZ1T3b//UzZugvW115lgJADgGxxl5eWTEkqGDG/49RDVaGUzOFYBtXYVFRdXps4yLFzqNJmpBgEAnzt474vim/6v6p/Pcewwm8Gd3zCyrs6Sv75s4lTbvp+oBgEA3/0U5zDlLi8acJP19TcphnDGZnACU0Bnfm74+JOy8fHVr+zkMUOBA2HgDylwqrRs3MTAmwdF5CyV9+1DQU5vBcEqoMbXSUmJKTO3nkcLGQHALz/ZFd1ws+GFRa7aWqrxWwAITAH9xlZvKdhcPmEKvT8BAMGPD+Y2LskqvvGW2n/9h2JImAISBOG3A3tj46u3bnPZ7VRDYAoIgr8fO3zqwUeC77kzbOHz8pgYUd8EFvcqIGdpqWn5qrovvuJNwQgA4lLz9nvF199sXJot2GziPRNYtFNAdnv11m1lcZPp/QkAiJSrvt4wf2HRDTfX/fcTMf79CqU4t4Kw/W9vedxkS8FmV0MD7wKBKSCImf3Y8ZJhD6qG3Rf2wrOynj1EthuouN4CjooKy6r8WnHmPRgB4Gysu98oGjDQlLdCEM2dQFFNAUkcDusrO8vHT6L3x+mr4oiuG1VAY4pLLo7IyQi44ToRLHs/Zftxn0SvF0RwYK9xSZb9xAkubxAAOLeQkSNCn3taFhnhx3+js7Ky/od9kpAQP/4bXQaDac06Vv1CYAoIbVe9fWfRgJvMq9cKDof/3gMI8OMHwSROZ81rr5eNn0TvD0YAaCflZf3CczICrr3GLxdB2b7f65LJ/O9Pa/jlF2NGrv3YMS5gEADoKPWY0aHPPCH1u+nyuq+/9bdUM5vNazfUvPMeFy0EpoDgFpbNW4r+eoNl44v+diqIxJ/6fmfNnrfLxk2k9wcjAHQK5ZVXRCzPUV7e3z/+nPpvv3f5xabH9qNHjYszGw4f4RIFAYBOvWokmgmx+ifmSLVanw+A7//nsvv2XW6Xtdq8flPNm3s4shECU0DwxLHDazcUXTuw+qXtfhBmPt0Ste9/UBYbX/PGW/T+YAQATwu4fkBETobi0kt8dQSw90eXb+6FZz9eaMrMsf18gIsQBAC6cBgp1U6J18+ZKVH73hNV9T/sc9XX+9iLrq01b3zR+trrHNkIAgBeQRYZEbbgOdUDw30sAPb95Kqt86EXXPfhR+aV+Q6DgUsOBAC8S+DAGyOWZfvQscO2n/Y7a3zjgExHcbExM9e27ycuMxAA8FYKhW76VF16siQ42AcCYP8Bp9UqeP0Ty9Yt2yzbdzDnAwIAPkAW1TN80fzgIfd4ewAc+MVpqfbmV1j32efm5asc5RVcVCAA4EuC/nFreNZibz522PbLQafZInjrgb3G7Lz6b7/nQgIBAN+kVOpTE7XJMyQBAd4YAAd/dZrM3veybNUv76jetp0jG0EAwOfJY6LDMxcH3fZ3r+tpDx12Goxe9ZLqv/nWlL3MUVbGZQMCAP4jeMg9YQuek0f38p6X1HD4iKPKW5ZUOsvKTCvX1H36OZcKCAD44wUXFKSbmaKbPtVLTmJpOHLUUVnV9a/DYbe+ssuyeQtzPiAA4OcUF14Qnr008G83dX0AHD3mqKjs2tdg+3GfKSvXXsyBvSAAIBqqEfeHvfBs1x473HC80FFWLnTdgb3GlWvqPvwvFwMEdgOFqFh37iq65gbTyjWC3S623UAlDof11V2l4ybS+4MRAERNccnFETkZATdc5/lfbS8qtp8q9fSwY//Pxswce2ERTQ8CABAEQQh59OGwZ56Uhod7NABOnLCfPOWxX+cyGs3562ve/xfNDYEpIOBP1VtfLhow0LyuwKM73kiknjuw9403y2Lj6f3BCAAQWjt2ODdDedWVnhgBlJzywPIb+6FDxowcDuwFAQC0iTp2TOhT86R6fed2zaWl9sLiTvzcb7GY1xXU7HmHBoXAFBDQRpaCzUXXDrS8uNV3VwHV7Hm7LDae3h+MAIB2Crjmr+E5GcrL+3fGD3eUVzQcO+7+gcXRo8aMnIaDv9J8IACAjn5O10yaEDpvtkSjdnMAVFQ2HD3mxh/oslotBZutr78puFy0GwSmgIAOd6su8+q1hdfcWL19p7vfAe6cAqr793/KYidad79B7w9GAIDQGccOh2cvVVx0oXtGAAZjw6HDHNgLAgDwETKZNmGyfna6RNXRY4edRpPt10Md+hG1tZYXX6reuYsDe0EAAJ5Kge7dwhY8pxo+tEMBYDLbOnCrtu6jj02r1ji9YUNpgACA2ATePCgiZ6m8bx/Bs6uAHCUlpszc+r0/0AQgAICuo1DokqbpUpMkQUGCB7aDttVbtm63bt/h6sJNTAECAPiTLKpnRE7G+R47bPv5gLPa2vbvr//iS1PeCkd5BQUHAQB4l+B77gxb+Lw8JqYt31z3+ZcNB39V9O8ntO3AXmPu8vqvvqHIIAAAb72mAwJ06Sm6xARBqWz19q+p+PpBgt0evjxHGhbW2k9saKjevrN66zYO7AUBAPgAeZ/eETkZgbcMarlL//VQ6aPjfnsCQB4VFb4sU6IKafE7bf/ba8rMtZ86RUlBAAC+JOiO27TxcUF33PbnVxwnS6yvv1n19POu+vrTbwN1iOqO24IH3yOLiT7d9X/1tfWNPXVffkUZQQAAPnuVBwbKY6KlOq3t5wMuS3Vr44boXlK93mU0NpwqFWw2SgcCAAAgsBkcAIAAAAAQAAAAAgAAQAAAAAgAAAABAAAgAAAABAAAgAAAABAAAAACAABAAAAACAAAAAEAACAAAAAEAACAAAAAEAAAAAIAAAgAAAABAAAgAAAABAAAgAAAABAAAAACAABAAAAACAAAAAEAACAAAAAEAACAAAAAEAAAAAIAAEAAAAAIAAAAAQAAIAAAAAQAAIAAAAAQAAAAAgAACAAAAAEAACAAAAAEAACAAAAAEAAAAAIAAEAAAAAIAAAAAQAAIAAAAAQAAIAAAAAQAAAAAgAAQAAAAAgAAAABAAAgAAAABAAAgAAAABAAAAACAABAAAAAAQAAIAAAAAQAAIAAAAAQAAAAAgAAQAAAAAgAAAABAAAgAAAABAAAgAAAABAAAAACAABAAAAACAAAAAEAACAAAAAEAACAAAAAEAAAAAIAAEAAAAABAAAgAAAABAAAgAAAABAAAAACAABAAAAACAAAAAEAACAAAAAEAACAAAAAEAAAAAIAAEAAAAAIAAAAAQAAIAAAAO3z/5VvJz9zX7GOAAAAAElFTkSuQmCC', 'base64'),
  };
  app.get('/pda/manifest.webmanifest', (req, res) => {
    const base = 'https://' + (req.headers['x-forwarded-host'] || req.headers.host);
    res.set('Content-Type', 'application/manifest+json; charset=utf-8');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(JSON.stringify({
      name: 'Colispo PDA', short_name: 'Colispo PDA', description: 'Terminal de scan des colis Tiinda et Coolibo',
      id: 'https://tiinda.com/pages/pda', start_url: 'https://tiinda.com/pages/pda', scope: 'https://tiinda.com/pages/',
      display: 'fullscreen', display_override: ['fullscreen', 'standalone'], orientation: 'portrait',
      background_color: '#DE1017', theme_color: '#DE1017', lang: 'fr',
      icons: [
        { src: base + '/pda/icone-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
        { src: base + '/pda/icone-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
        { src: base + '/pda/icone-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
      ],
    }));
  });
  app.get('/pda/icone-:t.png', (req, res) => {
    const img = ICONES_PDA[req.params.t];
    if (!img) return res.status(404).end();
    res.set('Content-Type', 'image/png'); res.set('Cache-Control', 'public, max-age=604800');
    res.send(img);
  });

  /* PDA : un agent connecté (identifiant + mot de passe + Google Authenticator) peut scanner.
     server.js l'utilise dans requireScan (en-tête x-op-session). */
  return {
    async verifierSessionScan(tok) {
      try {
        const d = lire('op', tok);
        if (!d || !d.id || !db) return false;
        const { data: op } = await db.from('operateurs').select('id, actif').eq('id', d.id).maybeSingle();
        return !!(op && op.actif);
      } catch (e) { return false; }
    },
  };

};
