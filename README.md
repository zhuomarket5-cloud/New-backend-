# ZhuoMarket Backend — PHOTO READY

Backend Express prêt pour Render.

## Upload photo
Route réelle:
POST /api/uploads

Le backend accepte les champs multipart:
- `image`
- `file`
- `photo`
- et tout autre nom de champ multipart

Formats: JPG/JPEG, PNG, WEBP, GIF
Taille max: 8 MB par image.
Le backend renvoie `url`, `image`, `imageUrl`, `fileUrl` et `path`.

## Déploiement Render
- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`

Variables:
- `JWT_SECRET` = une longue valeur secrète
- `ADMIN_EMAIL` = Gmail/email admin
- `ADMIN_PASSWORD` = mot de passe admin
- `FRONTEND_URL` = URL exacte du frontend Vercel (ou `*` pour test)

## Important
Les fichiers uploadés sont stockés dans `/uploads`. Sur Render, le disque local est éphémère sur les services sans disque persistant.
Pour une production où les photos doivent survivre aux redéploiements/restarts, il faudra ensuite brancher Cloudinary ou un stockage objet persistant.

## Compte admin initial
Créé automatiquement avec ADMIN_EMAIL / ADMIN_PASSWORD au premier démarrage.
Change les variables avant la mise en production.
