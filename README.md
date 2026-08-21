# 🔐 Keyra — OAuth2/OIDC Edition

A variant of [Keyra](https://github.com/vaalemax/keyra) (the original standalone password manager) rebuilt to delegate
identity entirely to a custom-built OAuth2/OIDC authorization server — exploring what
changes, architecturally and security-wise, when authentication moves from "the app owns
your credentials" to "the app trusts a third party's tokens."

This is the companion project to **[authserver](#)**, a Keycloak-inspired authorization
server built from Spring Authorization Server with multi-tenant realms and a custom
ABAC/RBAC engine. This repository shows that server actually being used by a real
application, not just tested in isolation.

> Looking for the original, self-contained Keyra (local login, master-password-derived
> encryption, TOTP as a second login factor)? See the [original repository](https://github.com/vaalemax/keyra).

---

## 🎯 Why this project exists

The original Keyra explores how to build a security-conscious application end to end.
This one explores a different, equally common problem: **how do you integrate a real
application with an identity provider you don't control** — handling the Authorization
Code + PKCE flow correctly, mapping OIDC claims onto local application state, and deciding
what still belongs in your own database once authentication is no longer your job.

It's also a study in a subtler distinction that's easy to blur: the difference between
**authentication** (who are you — entirely delegated to authserver) and **authorization**
(what are you allowed to do — split deliberately across two layers, a coarse local role
check for UI convenience and a real-time call to authserver's ABAC engine for actual
enforcement).

---

## ✨ Key Features

- 🔑 **Delegated login via OAuth2/OIDC** — no local password form. Login redirects to
  authserver's `keyra` realm, completes an Authorization Code + PKCE exchange, and
  provisions a local shadow user on first sign-in.
- 🏢 **Realm-isolated identity** — `keyra` is its own realm on authserver, with its own
  users, signing keys, and issuer — isolated from other applications registered on the
  same authorization server.
- 🛡️ **TOTP as a vault unlock, not a login step** — two-factor authentication protects
  *access to the vault* after login, independent of the OAuth2 session. Optional per user;
  the vault page itself renders the unlock prompt or the vault depending on state.
- 📜 **ABAC-gated activity log** — the `/activity` page isn't hidden by a local flag; every
  request calls authserver's `/auth/can` endpoint live, asking "can this token's holder
  view audit-log entries in this realm?" The local `hasRole('ADMIN')` check in the
  navigation bar is UI convenience only — it can hide a link from someone who'd technically
  be allowed to see it, but it can never grant access the backend call would deny.
- 🔐 **Encrypted vault** — credentials are still encrypted with AES-256-GCM (see
  [Known Limitations](#known-limitations) for how key derivation differs from the original).
- 🎲 **Password generator**, 📦 **vault export/import**, 🗂️ **categorized credentials** —
  unchanged from the original.
- 🚦 **Rate limiting** and 📜 **audit trail** — unchanged from the original.

---

## 🏗️ What changed, architecturally

```
Original Keyra:  Browser → Keyra (owns login, password hash, 2FA-at-login)
This edition:     Browser → Keyra → authserver (owns login, password hash, identity)
                              ↓
                        Keyra keeps only a shadow User row (username, provisioned
                        encryption key material, vault-unlock 2FA state) tied to
                        the OIDC subject.
```

A few concrete consequences of that shift:

- **`User.passwordHash` is an unusable placeholder.** No code path ever compares it —
  authentication happens entirely on authserver's side. It exists only because the column
  is `NOT NULL` in a schema that predates this change.
- **Two authorization systems, deliberately kept separate.** `User` roles used for local
  `hasRole(...)` checks are a coarse signal for UI rendering. Real enforcement for anything
  security-sensitive goes through `AuthorizationClient`, which calls authserver's
  `/{realm}/auth/can` with the caller's access token and gets back a live decision — not a
  cached role, an actual answer computed from that user's current role and permission
  assignments on authserver.
- **No local registration.** Users are provisioned on authserver (via its Admin API or
  Admin Console) and appear in Keyra automatically on first login. There's no `/register`
  page in this edition.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3 |
| Identity | OAuth2 Client (Authorization Code + PKCE) against a custom Spring Authorization Server |
| Security | Spring Security 6, BCrypt, AES-256-GCM, TOTP (Google Authenticator) |
| Persistence | Spring Data JPA (Hibernate), PostgreSQL |
| Schema migrations | Liquibase |
| Web layer | Spring MVC, Thymeleaf, `sec:authorize` for role-based rendering |
| Build | Maven |
| Other libraries | Lombok, Jackson, ZXing (QR code generation), Google Authenticator library |

---

## 🔒 Security Highlights

- **No credentials in this codebase.** Keyra never sees, stores, or verifies a password —
  that responsibility belongs entirely to authserver.
- **PKCE-protected Authorization Code flow**, validated end to end against a real
  authorization server, not a mocked identity provider.
- **Two-factor authentication (TOTP)** gates vault access independently of login, with
  single-use backup codes for recovery.
- **Authorization enforced remotely, not just checked locally** — the `/activity` endpoint
  is only reachable if authserver's ABAC engine says so *at request time*, not based on a
  role cached at login.
- **CSRF protection**, **Content Security Policy**, **secure cookie flags**, and **full
  audit logging** — unchanged from the original.

---

## ⚠️ Known Limitations

Same commitment to honesty as the original — here's what this edition trades away, and
why:

- **The "zero-knowledge" encryption guarantee of the original Keyra does not hold here.**
  In the original, the vault's AES key is derived from a master password the server never
  stores — direct database access reveals nothing readable. In this edition, the
  encryption key is generated **randomly at provisioning** and stored (salted, but without
  a user-held secret protecting it) alongside the user record. This was a deliberate
  scope decision: the goal of this fork was to prove out OAuth2/OIDC integration and ABAC
  enforcement, not to redesign vault cryptography around a login flow that no longer
  collects a user-known secret. A production-grade version of this edition would introduce
  a **separate vault passphrase** — never sent to authserver, known only to the user,
  used solely to derive/unwrap the encryption key at unlock time. That redesign is a
  known next step, not an oversight.
- **No master password change flow.** Since there's no master password in this flow, the
  original's password-rotation feature doesn't apply and has been removed rather than
  left in a broken state.
- **Provisioning is admin-driven, not self-service.** New users are created on authserver,
  not through a Keyra registration page.
- **Rate limiting is in-memory and per-instance** — same limitation as the original.
- **CSP allows `'unsafe-inline'`** for a small number of server-rendered inline scripts —
  same limitation as the original.
- **IP detection trusts proxy headers** — same limitation as the original.

---

## 🚀 Running Locally

This edition depends on **authserver** being up and reachable, with a `keyra` realm and a
registered client before Keyra itself will start a usable login flow.

### 1. Start authserver first

Follow the setup in the [authserver repository](#) — you'll need the `keyra` realm created
and a client registered with a redirect URI matching this app's callback
(`http://localhost:8081/login/oauth2/code/keyra` by default).

### 2. Configure Keyra's OAuth2 client registration

`src/main/resources/application.properties` (or environment variables):

```properties
spring.security.oauth2.client.registration.keyra.client-id=keyra-web
spring.security.oauth2.client.registration.keyra.client-secret=YOUR_CLIENT_SECRET
spring.security.oauth2.client.registration.keyra.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.keyra.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}
spring.security.oauth2.client.registration.keyra.scope=openid,profile

spring.security.oauth2.client.provider.keyra.issuer-uri=http://localhost:9000/keyra
```

### 3. With Docker (recommended)

```bash
git clone https://github.com/vaalemax/keyra-oauth2.git
cd keyra-oauth2

cp .env.example .env
# edit .env with your authserver client-id/secret

docker compose up --build
```

The app will be available at `http://localhost:8081`.

**Requirements:** Docker and Docker Compose, plus a running authserver instance.

### Without Docker

```bash
git clone https://github.com/vaalemax/keyra-oauth2.git
cd keyra-oauth2

cp .env.example .env
mvn spring-boot:run
```

---

## 📸 Screenshots
<img width="513" height="294" alt="image" src="https://github.com/user-attachments/assets/4ed7e033-667b-4a83-ad4e-1226e5414f95" />

<img width="1918" height="904" alt="image" src="https://github.com/user-attachments/assets/ac78b708-217b-4ac0-90b9-611d7dd36905" />

<img width="1919" height="905" alt="image" src="https://github.com/user-attachments/assets/bfa0bec9-1173-4c6b-a2ee-52edccdc38a3" />

---

## 📄 License

This project is available for portfolio/demonstration purposes.

---

Built by **Valerio Massimo Moretti** · Software Engineer
