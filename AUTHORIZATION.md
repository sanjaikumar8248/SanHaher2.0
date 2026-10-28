# SanHasher 2.0 Account Authorization

SanHasher 2.0 uses self-registration with Higher Authority approval. There is no "pre-provisioned-only" restriction — anyone can request an account from the login page, including a request to become Higher Authority.

## Account lifecycle
1. The user opens `/register` and submits their name, email, mobile, requested role, and a password.
2. **Bootstrap exception:** if no active Higher Authority account exists yet, a registration requesting role `HIGHER_AUTHORITY` activates immediately, since there is no one yet who could approve it. That registration also sets a second, separate profile-view password.
3. **Every other registration** — any role, including additional Higher Authority officers once the first one exists — is created `PENDING` and cannot log in.
4. An existing Higher Authority officer reviews pending registrations on the Authority dashboard and approves or rejects each one. Approval creates a new immutable access-grant event and notifies the user.
5. Once active, the user logs in at `/login` with their email or mobile plus their password.
6. SanHasher checks the account is active/verified, then generates a login OTP. The current development build displays the OTP locally; a production deployment should connect an approved SMS/email OTP provider.
7. The user enters the OTP and is admitted.
8. Login/logout, registration, approval/rejection, and OTP events are written to the security audit log.

## Higher Authority — two passwords
A Higher Authority account has two independent passwords:
- **Login password** — gets the officer into the app, same as any other user.
- **Profile-view password** — set at registration (or later from the "Profile-View Password" page) — required, together with a fresh OTP, every time the officer opens another user's full profile. The two must differ.

## Password resets
Users cannot reset their own password. They submit a request at `/forgot-password`; a Higher Authority officer approves or rejects it from the Authority dashboard. Approval issues a one-time temporary password that must be relayed to the user through a secure channel.

## Alternate provisioning (optional)
An administrator with access to the server can still run, from the project directory:

```cmd
python -m sanhash.provision
```

This CLI tool creates an already-verified account directly in the database, bypassing the approval queue. It remains available for trusted local administration but is not required — all normal account creation happens through the website.

## Important
Email/mobile and password are both required to log in; the OTP is a required second factor on top of that.
