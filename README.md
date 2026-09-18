# LONALOTO — version serveur (données partagées)

Cette version fonctionne avec un vrai serveur (Node.js + Express) et une base
de données PostgreSQL. Contrairement au fichier `.html` seul, **toutes les
personnes qui utilisent l'application voient et modifient les mêmes
données**, quel que soit leur appareil.

Vos données actuelles (RICHMOND, ANGE, Activité 3, Activité 4, juillet 2026 à
juillet 2027) sont déjà intégrées : au tout premier démarrage, le serveur les
enregistre automatiquement dans la base.

## Déploiement sur Render (recommandé)

Vous avez déjà un compte Render avec un espace de travail actif — voici la
suite.

### 1. Mettre ce dossier sur GitHub

Render déploie à partir d'un dépôt Git. Pas besoin de connaître `git` en ligne
de commande :

1. Allez sur [github.com/new](https://github.com/new) et créez un dépôt (par
   exemple `lonaloto`), en privé si vous préférez.
2. Sur la page du dépôt vide, cliquez **« uploading an existing file »**.
3. Glissez-déposez tous les fichiers de ce dossier (`server.js`,
   `package.json`, `render.yaml`, `.gitignore`, le dossier `public/` avec
   `index.html` à l'intérieur) et validez (« Commit changes »).

### 2. Déployer sur Render avec le Blueprint

Le fichier `render.yaml` inclus décrit tout ce qu'il faut : le service web
**et** la base de données PostgreSQL, déjà reliés entre eux.

1. Dans votre tableau de bord Render, cliquez **New +** (en haut à droite)
   puis **Blueprint**.
2. Connectez le dépôt GitHub que vous venez de créer.
3. Render détecte `render.yaml` et propose de créer :
   - un **Web Service** nommé `lonaloto`
   - une base **PostgreSQL** nommée `lonaloto-db`
4. Cliquez **Apply**. Le premier déploiement prend 1 à 3 minutes.
5. Une fois prêt, Render vous donne un lien du type
   `https://lonaloto.onrender.com` — c'est votre application, en ligne,
   accessible à tous.

### 3. Nom de domaine personnalisé (optionnel)

Dans les réglages du service web (`Settings` → `Custom Domains`), ajoutez
votre domaine et suivez les instructions DNS affichées par Render.

## À savoir sur le plan gratuit

- Le service web gratuit **se met en veille après 15 minutes** sans visite.
  La page suivante met alors 30 à 50 secondes à se réveiller — normal, pas
  un bug.
- La base PostgreSQL gratuite **expire 30 jours après sa création**. Pour des
  données réelles d'activité sur plusieurs mois, il est recommandé de passer
  la base en formule payante (« Starter », autour de 7 $/mois) avant
  l'expiration : Render vous préviendra par email et propose une mise à
  niveau en un clic, sans perte de données.

## Développement local (optionnel)

```bash
npm install
DATABASE_URL=postgres://user:password@localhost:5432/lonaloto npm start
```

L'application est alors accessible sur `http://localhost:3000`.
