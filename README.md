# Tennis Court Booking — Deployment Guide

Deploy for free in ~20 minutes using **Render** (hosting) + **Neon** (database) + **Twilio** (SMS).

---

## Step 1 — Database (Neon) — free forever

1. Go to **https://neon.tech** and sign up (free)
2. Create a new project → name it `tennis-court`
3. In the dashboard, click **SQL Editor** and paste the entire contents of `schema.sql` → Run it
4. Go to **Dashboard → Connection Details** → copy the **Connection string** (it looks like `postgresql://...`)
5. Save this — you'll need it in Step 3

---

## Step 2 — SMS (Twilio) — optional but recommended

Without Twilio the app still works — SMS codes are printed to the server logs instead (fine for testing).

1. Go to **https://twilio.com** and sign up (free trial gives ~$15 credit, enough for hundreds of SMS)
2. In the Console, copy your **Account SID** and **Auth Token**
3. Go to **Phone Numbers → Get a number** → pick an Israeli or international number
4. Save the three values: Account SID, Auth Token, Phone Number

---

## Step 3 — Hosting (Render) — free tier

1. Push this project to a GitHub repository:
   ```bash
   git init
   git add .
   git commit -m "initial commit"
   # create a repo on github.com, then:
   git remote add origin https://github.com/YOUR_USERNAME/tennis-court.git
   git push -u origin main
   ```

2. Go to **https://render.com** and sign up (free)

3. Click **New → Web Service** → connect your GitHub repo

4. Configure:
   - **Name:** tennis-court (or anything you like)
   - **Runtime:** Node
   - **Build command:** `npm install`
   - **Start command:** `node server.js`
   - **Instance type:** Free

5. Add **Environment Variables** (click "Add Environment Variable" for each):

   | Key | Value |
   |-----|-------|
   | `DATABASE_URL` | your Neon connection string |
   | `SESSION_SECRET` | any long random string (e.g. run `openssl rand -hex 32`) |
   | `NODE_ENV` | `production` |
   | `TWILIO_ACCOUNT_SID` | from Twilio (or leave empty) |
   | `TWILIO_AUTH_TOKEN` | from Twilio (or leave empty) |
   | `TWILIO_PHONE_NUMBER` | from Twilio (or leave empty) |

6. Click **Deploy** — Render will build and deploy automatically

7. Once deployed, Render gives you a URL like `https://tennis-court-xxxx.onrender.com` — that's your app!

---

## Step 4 — First login

- Open your app URL
- Sign in with phone `000 0000000` and PIN `0000`
- **Immediately go to your profile and change the admin PIN!**
- Share the app URL with your tenants

---

## Notes

- **Free tier cold starts:** Render's free tier spins down after 15 minutes of inactivity. First load after inactivity takes ~30 seconds. Upgrade to the $7/month plan to avoid this.
- **SMS in dev mode:** If Twilio credentials are not set, SMS codes are printed to Render's logs (Dashboard → your service → Logs). You can retrieve them manually for testing.
- **Sessions:** Sessions are stored in memory by default. For production with multiple instances, swap `express-session` for `connect-pg-simple` to store sessions in Postgres (the package is already in package.json).

---

## Local development

```bash
cp .env.example .env
# fill in DATABASE_URL in .env (from Neon)
npm install
node server.js
# open http://localhost:3000
```
