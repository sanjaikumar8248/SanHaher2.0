# SanHasher 2.0 — Forensic Cryptography & Evidence Integrity Suite

## Want this reachable at a real URL, for free?
See **DEPLOY.md** for a concrete, step-by-step guide to deploying this for free on
PythonAnywhere with persistent storage and genuine email-delivered OTPs (not the
on-screen demo mode) — including how to set up a free Gmail App Password for sending them.

## Authority-Controlled Evidence Governance

This build implements a strict Higher Authority security layer.

### Higher Authority only
- Create/provision user accounts.
- Grant and revoke user access.
- Change user roles; every change is a new immutable access event.
- View every authorized user profile. Profile access itself is logged.
- Delete evidence. Analysts/examiners cannot delete evidence.
- Restore evidence during the 30-day Recently Deleted recovery window.
- View the global application audit log and immutable Access Grant Register.

### No permanent deletion
There is intentionally **no permanent-delete function** anywhere in the application.

When Higher Authority deletes evidence:
1. The evidence is marked `DELETED`.
2. Its original bytes, versions, SHA-256, custody history, and metadata remain retained.
3. It enters the Recently Deleted area for 30 days.
4. Every authorized user receives a mandatory in-app notification.
5. Higher Authority can restore it during the 30-day recovery window.
6. After 30 days it becomes `ARCHIVED_30D_EXPIRED`; it remains retained and is not physically erased.

### Immutable access register
Every access event receives:
- Grant/Event ID
- User
- Role
- Action
- Higher Authority who performed it
- Exact date/time
- Notes
- Previous event hash
- Current event hash

The access register is hash-chained. Changing an earlier event causes the integrity check to fail.

### Mandatory notifications
Evidence deletion and restoration generate notifications for every authorized user. Notifications are also recorded in the database and displayed in the application.

### Evidence upload — two tiers (v2.4)
Every case page has two upload paths now, so file size decides which one to use:

- **Small files (roughly up to 150 MB)** — the original "Add Evidence" form: pick a file, one HTTP POST, the server hashes and registers it. Simple, fine for photos, documents, logs, small disk images.
- **Large files (GB-scale, resumable)** — a second "Add Large Evidence" panel on the same page, for forensic disk images, large exports, anything from a few hundred MB up into the hundreds of GB. The browser splits the file into 16 MB chunks and uploads them one at a time against a server-tracked byte offset (`POST .../evidence/chunked/start` → repeated `PATCH .../evidence/chunked/<session_id>` → `POST .../evidence/chunked/<session_id>/finish`). The server never buffers more than one chunk in memory, and the SHA-256 is computed by streaming the assembled file in 1 MB reads, so memory use stays flat regardless of file size.
  - **Resumable:** if the connection drops or the tab is closed mid-upload, reselecting the same file (matched by name + size + last-modified) picks up from the last byte the server actually received instead of restarting. The in-progress session id is kept in the browser's `localStorage`; the server is the source of truth for how many bytes it actually has.
  - **Self-correcting:** every chunk carries the offset the browser believes it's at; if that doesn't match what the server has (two tabs, a retried request after an ambiguous timeout), the server rejects it with the real offset instead of silently corrupting the file, and the client resyncs.
  - **Isolated:** an upload session is scoped to the user and room that started it (and the existing per-case membership check) — another officer's room, or another user in the same room without case access, gets a 404, not someone else's in-progress file.
  - Evidence registered this way goes through the exact same `add_evidence` / custody-log / Merkle-rebuild path as a small upload, so nothing downstream (verification, versioning, deletion, audit) treats it differently.
- `MAX_CONTENT_LENGTH` is set so no single HTTP request (the whole small-file form, or one large-file chunk) can exceed about 214 MB — this is what forces genuinely large files onto the chunked path rather than letting a huge single POST hang or blow up memory.

**Scope / research gap:** this chunked uploader is a from-scratch, dependency-free implementation of the core resumable-upload idea (the same one tus.io formalizes), built to work without any external service. It has not been load-tested at true multi-hundred-GB scale or under concurrent many-user load, there's no parallel-chunk upload (chunks go sequentially), and evidence still lands on local disk rather than object storage (S3/MinIO) or a proper evidence NAS. Treat it as a working prototype of the right architecture, not a production-hardened ingestion pipeline — scaling it further (parallel chunks, object storage backing, a real tus-compliant server, acquisition-time hashing for true forensic images) is the natural next step, not something this build claims to have solved.

### Account access model (v2.3 — multi-room)
- **Everyone registers on the website — no terminal needed.** Go to `/register` for every role, including Higher Authority.
- **Each Higher Authority officer owns an independent room.** Registering as `HIGHER_AUTHORITY` immediately creates a brand-new room and activates the officer as its sole administrator — no approval needed, since they're founding their own space. The app returns a permanent **Room / Registration ID** right after registration and shows it on the Authority dashboard at all times.
- **Room ID format.** The ID is built from the officer's own data at the moment of registration: `<last 4 digits of their mobile number><DDMMYY><HHMMSS>` (e.g. a mobile ending `3210`, registered on 5 Oct 2026 at 06:12:13, gets `3210051026061213`). It never changes afterward.
- **One mobile number = one account = one room.** Mobile numbers are globally unique across the whole system, so a given number can register (and therefore own) only one room, and can only ever belong to one account.
- **Members join a specific room by its Registration ID.** A member registers at `/register`, picks a non-Authority role, and enters the Room ID their officer gave them. The request is `PENDING` and visible only to that room's officer; no other officer can see or approve it.
- **Any number of rooms can coexist.** Many different mobile numbers can each register their own Higher Authority account/room; each is fully isolated — separate pending queues, separate member lists, separate cases/evidence, separate audit log and access-grant register, separate notifications.
- An additional Higher Authority account is just another independent room — it is not nested under, or approved by, any existing officer.
- The old `python -m sanhash.provision` CLI tool still works as an optional alternate way to create a room/officer or add an already-approved member from a trusted machine, but it is no longer required.
- **Login = password + OTP.** Login is by email or mobile, plus the account's password, plus a one-time OTP sent to complete the sign-in. (Local/dev builds display the OTP on screen; wire a real SMS/email provider for production.)
- **Higher Authority has two separate passwords.** The login password gets the officer into the app. A second, independently-set **profile-view password** — plus a fresh OTP — is required every time the officer opens a member's full profile, and only works for members of their own room. Set/change it under "Profile-View Password" in the nav.
- **Password resets require approval.** Members can't reset their own password. They submit a request at `/forgot-password`; it goes to their own room's officer only, who approves or rejects it from the Authority dashboard and issues a one-time temporary password to relay securely. The member should change it immediately afterward from "Change Password".
- **Evidence deletion stays Higher-Authority-only and notifies that room.** Deleting evidence soft-deletes it into Recently Deleted for 30 days and sends a mandatory notification to every member of the same room. There is still no permanent-delete function anywhere in the app.

### Existing SanHasher features retained
- Text hashing: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3 family, BLAKE2b/BLAKE2s
- Base64 encoding
- File hashing and metadata
- Password hash analysis and offline dictionary matching
- Automatic hash identifier
- File hash comparison
- Hash → Text recovery using an uploaded offline wordlist
- Case management
- Evidence manifest
- Evidence view/download logging
- Individual and case integrity verification
- Evidence versions with original preservation
- Merkle tree
- Tamper detection
- Chain of custody
- Forensic reports
- Recently Deleted / 30-day recovery
- Authentication with pre-provisioned accounts + OTP
- Green/black forensic UI

## Run on Windows

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open:

`http://127.0.0.1:5000` and click **Register for access**. Choose role `Higher Authority (Officer)` to create your own room — it activates immediately, no approval needed, since you're founding it — and set both your login password and your separate profile-view password on that same form. You'll be shown your permanent Room / Registration ID right after.

## Officer (Higher Authority) workflow

1. Register as Higher Authority at `/register` (see above). This creates a new, independent room and gives you a permanent Room ID such as `3210051026061213`.
2. Log in at `/login` with your email/mobile + password, then complete the OTP.
3. Open **Higher Authority** from the navigation — your Room ID is shown at the top. Share it with the people you want in your room.
4. Members who register with your Room ID appear in your Pending Registrations queue; approve or reject each. Only you see requests for your own room.
5. Approving a registration grants that member access; they can then log in themselves with their own password + OTP.
6. To open a member's full profile, use **View Profile**, then enter your profile-view password and a fresh OTP — separate from your login password, required every time, and only works on members of your own room.
7. From a member's profile, change their role or revoke/restore access; every change is a new immutable access event scoped to your room.
8. Use your room's immutable Access Grant Register and **Audit Log** to review activity — only your own room's events are shown.
9. Evidence deletion is available only to you (Higher Authority) and always notifies every member of your room; deleted evidence sits in Recently Deleted for 30 days and can only be restored by you.
10. Multiple officers can register independently at any time — each gets their own isolated room, with no visibility into any other officer's members, cases, or data.

## Member workflow

1. Get the Room / Registration ID from your Higher Authority officer.
2. Register at `/register`, pick your role (Examiner/Analyst/Investigator), enter that Room ID, and wait for approval (you'll see a pending message if you try to log in early).
3. Once approved, log in with your email or mobile, your password, and an OTP.
4. Use the forensic tools, register evidence, and view your notifications (including mandatory alerts when evidence is deleted or restored) — all scoped to your room.
5. Forgot your password? Submit a request at `/forgot-password`; your room's officer must approve it and will relay a temporary password, which you should change immediately from "Change Password".

## Important prototype note
This is an academic forensic application prototype. For production forensic use, deploy with hardened secrets, HTTPS, a real OTP delivery provider, encrypted storage, OS-level access controls, trusted time, secure backups, and independently protected audit storage.

**Two of those are now wired in and real, not just advice:**
- **Secret key**: set `SANHASHER_SECRET` in the environment on any real deployment. If it's absent, the app refuses to fall back to a known hardcoded value — it generates a random one and persists it locally instead (fine for local dev, but a real deployment should always set this explicitly).
- **Real OTP email delivery**: set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` (and optionally `SMTP_FROM`) in the environment, and every OTP (login, Authority login, profile-view unlock, self-service password reset) is actually emailed instead of shown on screen. If sending fails or isn't configured, it falls back to the on-screen "local demo mode" display rather than locking anyone out. See **DEPLOY.md** for how to get a free Gmail App Password for this.

Set `SANHASHER_ENV=production` on any real deployment — this disables Flask's interactive debugger, which must never be reachable on a public URL.


## Updated case and Authority workflow

- **Authority Login** is a separate entry point.
- One Authority mobile creates one Authority account and one permanent Room.
- Authority can create many cases in that room.
- Team Lead assignment is optional when the Authority creates a case.
- Room members can request a case; Authority approval creates the case and makes the requester the Team Lead.
- A Team Lead cannot transfer a case without Authority action.
- Room membership does not automatically grant case access.
- Authority assigns members to individual cases.
- Assigned case members can view/download evidence and upload evidence working copies for hash comparison.
- Original evidence is registered as the immutable baseline and is never overwritten by working copies.
- Evidence uploaded by an assigned case member is stored in that case and its SHA-256 is recorded.
- Copy verification compares the submitted copy SHA-256 against the original registered SHA-256.
- Authority actions and case-access changes are recorded in the audit/access history.
- The interface uses a red/black theme.
