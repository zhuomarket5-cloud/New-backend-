# ZhuoMarket Backend — PHOTO READY V2

Backend Express prepared for Render and the current ZhuoMarket frontend.

## Important
- Real multipart image upload: `POST /api/uploads`
- Accepts the frontend's `image` field (and also other multipart field names).
- JPG/JPEG/PNG/WEBP/GIF, max 8 MB per image.
- Requires the user's Bearer token.
- Returns a public `/uploads/...` URL.
- Includes compatibility routes for products, promotions, admin users/orders, notifications, support messages, streaming orders/plans, payment methods, and auth.
- PayPal is NOT simulated. Until real PayPal credentials/integration are configured, its routes return a clear configuration error.

## Render
Build Command:
`npm install`

Start Command:
`npm start`

Set environment variables in Render:
- `FRONTEND_URL` = your Vercel frontend URL
- `JWT_SECRET` = a strong random secret
- `ADMIN_EMAIL` = primary admin email
- `ADMIN_PASSWORD` = primary admin password

## Photos on Render
The included upload folder uses local disk. Render's ephemeral filesystem can lose uploaded photos after a restart/redeploy unless you configure persistent storage or move uploads to an object-storage service such as Cloudinary/S3.

## First test after deployment
Open:
`/health`

Expected:
`{"ok":true,...}`

Then test login and finally photo upload from the ZhuoMarket app.
