# Deploying SanHasher 2.0 for free (PythonAnywhere)

This gets you a real, always-on, publicly reachable URL with persistent storage
and genuine email-delivered OTPs — not the on-screen demo mode.

## 0. Push the code to GitHub first

```bash
cd SanHasher-2.0-Evidence-Individual-Verification
git init
git add .
git commit -m "Initial commit"
```
Create a new (private is fine) repo on GitHub, then:
```bash
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

## 1. Get a free Gmail App Password (for real OTP emails)

Gmail won't accept your normal account password from code — you need an **App Password**.

1. Turn on 2-Step Verification on the Google account you'll send from: `myaccount.google.com/security`
2. Go to `myaccount.google.com/apppasswords`
3. Create one named "SanHasher", copy the 16-character password it gives you (spaces don't matter). This is your `SMTP_PASSWORD` below — **not** your real Gmail password.

(Any other SMTP provider works too — Outlook, a transactional-email free tier like Resend/Mailgun/SendGrid. Just change `SMTP_HOST`/`SMTP_PORT` accordingly.)

## 2. Create a free PythonAnywhere account

Sign up at `www.pythonanywhere.com` → "Beginner" (free) account.

## 3. Clone the repo and install dependencies

Open a **Bash console** from the PythonAnywhere dashboard:

```bash
git clone https://github.com/<you>/<repo>.git sanhasher
cd sanhasher
mkvirtualenv --python=python3.10 sanhasher-env
pip install -r requirements.txt
```
(PythonAnywhere runs your web app under its own WSGI mechanism, not gunicorn — you don't need `requirements-prod.txt` here.)

## 4. Create the web app

1. Dashboard → **Web** tab → **Add a new web app**
2. Choose **Manual configuration** (not one of the Django/Flask quickstarts) → pick the same Python version as your virtualenv
3. Under **Virtualenv**, set the path to the one you just made, e.g. `/home/<you>/.virtualenvs/sanhasher-env`
4. Under **Code**, set:
   - **Source code**: `/home/<you>/sanhasher`
   - **Working directory**: `/home/<you>/sanhasher`

## 5. Point the WSGI file at the app

Click the WSGI configuration file link on the Web tab (something like `/var/www/<you>_pythonanywhere_com_wsgi.py`). Delete its contents and replace with:

```python
import sys, os

project_home = '/home/<you>/sanhasher'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# --- required ---
os.environ['SANHASHER_ENV'] = 'production'
os.environ['SANHASHER_SECRET'] = 'paste-a-long-random-string-here'  # e.g. python3 -c "import secrets; print(secrets.token_hex(32))"

# --- optional but strongly recommended: real OTP emails instead of on-screen ---
os.environ['SMTP_HOST'] = 'smtp.gmail.com'
os.environ['SMTP_PORT'] = '587'
os.environ['SMTP_USER'] = 'your-gmail-address@gmail.com'
os.environ['SMTP_PASSWORD'] = 'the-16-char-app-password-from-step-1'
os.environ['SMTP_FROM'] = 'your-gmail-address@gmail.com'

from wsgi import application
```

Generate the random secret locally first:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```
and paste the result in — never commit this value to GitHub, never reuse the one in these docs.

## 6. (Optional) serve static files directly

Back on the Web tab, under **Static files**, add:
- URL: `/static/`
- Directory: `/home/<you>/sanhasher/static/`

This is a minor performance win; the app works without it too.

## 7. Reload and test

Click the big green **Reload** button on the Web tab. Your app is now live at
`https://<you>.pythonanywhere.com`.

1. Go there, click **Register for access**, choose **Higher Authority (Officer)**
2. Check the inbox of the Gmail address you entered as `SMTP_USER` — wait, actually the OTP goes to *your own* email (the one you registered with), not `SMTP_USER` — `SMTP_USER` is just the account SanHasher sends *from*. Register with any real email you can check.
3. You should receive an actual email with the OTP, not an on-screen "local demo mode" message. If you still see the demo-mode message, double check the WSGI file's `SMTP_*` values were saved and you clicked **Reload** again after editing it.

## Where your data lives

On PythonAnywhere, SanHasher's `paths.py` isn't in "frozen desktop" mode, so data is stored
relative to the project folder you cloned — `sanhasher/data/sanhash.db`, `sanhasher/uploads/`,
`sanhasher/cases/`, `sanhasher/reports/` — which **is** persistent storage on PythonAnywhere's
free tier (unlike Render's free tier, which wipes the filesystem on sleep/redeploy). Back up the
`data/` and `cases/` folders periodically regardless; this is still a prototype, not a
production evidence-management system with its own backup strategy.

## Known limits of this free path

- **Disk space**: PythonAnywhere's free tier caps you around 512 MB total. Large evidence uploads (the chunked/resumable Tier 2 uploader) will work correctly but you'll run out of room fast with real forensic images — fine for demos, not for real case storage at scale.
- **One worker, modest CPU**: fine for a handful of people using it at once; not meant for heavy concurrent traffic.
- **SQLite**: fine at this scale; would need to move to Postgres if usage grows significantly.
- **This still doesn't change the project's documented research gaps** (see the README's "Evidence upload — two tiers" and "Scope / research gap" sections) — deploying it doesn't make the large-file pipeline production-hardened, it just makes the existing prototype reachable by URL.

## Updating the live site later

```bash
# on PythonAnywhere, in a Bash console:
cd sanhasher
git pull
workon sanhasher-env
pip install -r requirements.txt   # only if dependencies changed
```
Then **Reload** the web app from the Web tab.

## Alternative: Render (if you'd rather not use PythonAnywhere)

Render's free tier is easier to connect to GitHub (auto-deploys on push) but its free
filesystem is **not persistent** — your database and evidence will be lost whenever the
app sleeps or redeploys, which happens automatically after 15 minutes of inactivity.
Only use this for a demo you don't mind resetting, not for real data. If you want this
path anyway: connect the GitHub repo, set the same environment variables as above in
Render's dashboard, and the included `Procfile` (`web: gunicorn wsgi:app --bind
0.0.0.0:$PORT --workers 2 --timeout 120`) is picked up automatically — no extra config needed.
