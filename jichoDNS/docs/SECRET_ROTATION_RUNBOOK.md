# Secret Rotation Runbook — ACTION REQUIRED

> Created 2026-07-06 as part of the `security-hardening` remediation.
> **These steps require a human operator with production + GitHub access. They are NOT performed automatically by the code changes on this branch.**

## Why

The 2026-07-06 audit found two ways the entire production secret set is exposed:

1. **`backend/app/core/config.py`** shipped `SECRET_KEY` with a hardcoded default
   (`dev-secret-key-change-in-production`). If the prod container ever booted without
   the env var set, that published value signs every JWT **and** the sqladmin session
   cookie → anyone can forge an admin session. *(Code fix on this branch adds a
   production fail-fast so the app refuses to boot with the placeholder.)*
2. **`ansible/group_vars/all/vault.yml`** is encrypted with a **guessable password**
   (project-name + year pattern). Anyone with a repo clone can decrypt it offline and
   read the prod SSH password, `SECRET_KEY`, and all DB/ES passwords.

**Treat every secret that has ever been in that vault or in an `.env` as compromised.**

## Rotation checklist (do in this order)

- [ ] **1. JWT `SECRET_KEY`** — generate a new 64-byte value:
      `python -c "import secrets; print(secrets.token_urlsafe(64))"`.
      Set it in the prod env / secret store. *Rotating this logs out all users and
      invalidates all issued JWTs — expected.* Use a **separate** value for the
      sqladmin session-cookie secret (see code fix).
- [ ] **2. Production SSH** — stop using a password. Deploy an SSH keypair for the
      `plover` deploy user, set `PasswordAuthentication no` in `sshd_config`, and
      remove the old password. Update the `SSH_PRIVATE_KEY` GitHub Actions secret.
- [ ] **3. Postgres / ClickHouse / Redis / Elasticsearch passwords** — rotate each,
      update the app env + `docker-compose` + Ansible vault. Ensure Redis requires a
      password (`requirepass`) and is not published to the host (see compose fix).
- [ ] **4. Stripe / Paystack** — rotate `STRIPE_SECRET_KEY`, set a real
      `STRIPE_WEBHOOK_SECRET` (the webhook now fails closed without it), rotate
      Paystack keys.
- [ ] **5. Any third-party API keys** that were in the vault/.env (Shodan, VT, HIBP,
      Censys, etc.) — rotate as a precaution.

## Vault password + git history

- [ ] **6. New vault password** — replace with a long random value stored ONLY in a
      password manager / the `ANSIBLE_VAULT_PASSWORD` GitHub secret. Re-encrypt:
      `ansible-vault rekey ansible/group_vars/all/vault.yml`.
- [ ] **7. Prefer a runtime secret store** — SOPS+age, HashiCorp Vault, or a cloud
      secret manager — over standing encrypted secrets in the repo.
- [ ] **8. Purge the old vault from git history** — AFTER rotating everything above
      (so the purge protects nothing still-valid, it just reduces exposure):
      `git filter-repo --path ansible/group_vars/all/vault.yml --invert-paths`
      (or BFG), then force-push and have all collaborators re-clone.
      **Coordinate this — it rewrites history.**

## Verification

- [ ] Confirm the app **refuses to boot** in production with the placeholder key
      (the new `config.py` validator) — `ENVIRONMENT=production SECRET_KEY=dev-secret-key-change-in-production python -c "import app.core.config"` should raise.
- [ ] Confirm SSH password auth is disabled: `ssh -o PreferredAuthentications=password plover@<host>` is rejected.
- [ ] Confirm the Stripe webhook rejects an unsigned test event (returns 400/500, not 200).
