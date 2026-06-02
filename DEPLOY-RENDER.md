# TIINDA — Activer l'OTP WhatsApp avant inscription (déploiement Render)

Objectif : vérifier le numéro WhatsApp **avant** d'accepter l'inscription.
Tu as déjà ton compte Twilio. Il reste 3 choses : (1) un Verify Service WhatsApp,
(2) déployer ce backend sur Render, (3) le relier à Shopify via App Proxy.

---

## 1. Côté Twilio — créer le Verify Service (WhatsApp)

1. Console Twilio → **Verify → Services → Create new**
2. Donne un nom (ex : `Tiinda OTP`) → tu obtiens un **Service SID** (`VA…`)
3. Dans le service, active le canal **WhatsApp** (Twilio fournit un modèle OTP
   WhatsApp pré-approuvé — pas besoin de ton propre numéro WhatsApp Business pour
   démarrer).
4. Note tes 3 valeurs (Console → Account Dashboard) :
   - `TWILIO_ACCOUNT_SID`  (commence par `AC…`)
   - `TWILIO_AUTH_TOKEN`
   - `TWILIO_VERIFY_SERVICE_SID`  (le `VA…` ci-dessus)

---

## 2. Déployer le backend sur Render (gratuit)

Ce dossier contient tout : `server.js`, `package.json`, `render.yaml`.

1. Crée un compte sur **render.com**
2. Mets ce dossier sur un dépôt **GitHub** (ou utilise « Deploy from Git »)
3. Render → **New → Web Service** → sélectionne le dépôt
4. Render lit `render.yaml` automatiquement. Sinon, règle à la main :
   - **Build Command** : `npm install`
   - **Start Command** : `node server.js`
   - **Plan** : Free
5. Onglet **Environment** → ajoute les 4 variables :
   ```
   TWILIO_ACCOUNT_SID        = AC……
   TWILIO_AUTH_TOKEN         = ……
   TWILIO_VERIFY_SERVICE_SID = VA……
   SHOPIFY_API_SECRET        = (rempli à l'étape 3)
   ```
6. **Deploy**. Quand c'est vert, ouvre `https://<ton-app>.onrender.com/health`
   → tu dois voir `{ "ok": true }`. Note bien cette URL.

> 💡 Le plan gratuit Render « s'endort » après inactivité : le 1er envoi de code
> peut prendre ~30 s. Pour un usage réel, un plan payant à quelques $/mois évite ça.

---

## 3. Relier à Shopify — App Proxy

1. Admin Shopify → **Paramètres → Apps et canaux de vente → Développer des apps**
   → **Créer une app** (nom : `Tiinda OTP`)
2. Onglet **Configuration → App proxy** :
   - **Subpath prefix** : `apps`
   - **Subpath** : `otp`
   - **Proxy URL** : `https://<ton-app>.onrender.com`
   - Enregistrer
3. Onglet **API credentials** → copie l'**API secret key** → remets-la dans Render
   comme `SHOPIFY_API_SECRET`, puis **redéploie** (Render → Manual Deploy).

Résultat : quand le thème appelle `tonsite.com/apps/otp/send`, Shopify relaie
vers ton backend Render, qui parle à Twilio. La signature garantit que seules les
requêtes venant de ta boutique sont acceptées.

---

## 4. Activer le mode réel dans le thème

Dans **`templates/index.liquid`** (ou `Tiinda Homepage.html`), cherche :
```js
var OTP_API  = '/apps/otp';
var OTP_LIVE = false;     // ← passe à true
```
Mets `OTP_LIVE = true`, enregistre, recharge la boutique.

✅ Désormais : à l'inscription, le client reçoit un **code WhatsApp**, doit le
saisir, et l'inscription n'est validée **que si le code est correct** —
exactement ce que tu veux.

---

## 5. Tester

1. Ouvre ta boutique, lance une inscription avec **ton propre numéro WhatsApp**
2. Tu dois recevoir le code sur WhatsApp
3. Bon code → accès à l'espace ; mauvais code → message d'erreur, pas d'accès

### Dépannage
| Symptôme | Cause | Solution |
|---|---|---|
| Pas de code reçu | Canal WhatsApp non activé / numéro mauvais format | Vérifie le Verify Service + numéro en E.164 (`+243…`) |
| `invalid signature` | `SHOPIFY_API_SECRET` absent/incorrect sur Render | Recolle la clé et redéploie |
| 1er envoi très lent | Render Free en veille | Normal ; passe en plan payant pour éviter |
| Rien ne se passe (code accepté sans envoi) | `OTP_LIVE` encore à `false` | Mets-le à `true` |
