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
};
