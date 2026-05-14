# Bug Finder — Operations Runbook

## RTO / RPO Targets

| Metric | Target | Notes |
|--------|--------|-------|
| **RTO** (Recovery Time Objective) | < 15 minutes | Time to restore service from last backup |
| **RPO** (Recovery Point Objective) | < 24 hours | Max data loss (daily backups) |
| **Uptime SLA** | 99.5% | ~3.6h downtime/month |

---

## Backup Strategy

Backups run daily via `mongo-backup` Docker service (mongodump → gzip → /backups/).
- Retention: 7 days rolling
- Format: `bugfinder-YYYY-MM-DD.tar.gz`
- Location: Docker volume `bugfinder_backups`

### Manual backup

```bash
docker-compose exec mongo-backup sh -c \
  'mongodump --host mongo --username $MONGO_USER --password $MONGO_PASSWORD \
   --db $MONGO_DB --archive=/backups/manual-$(date +%F).gz --gzip'
```

---

## Database Restore Procedure

### Step 1 — List available backups
```bash
ls -lh /backups/*.gz
```

### Step 2 — Run restore script
```bash
# Restore latest backup:
./scripts/restore.sh

# Restore specific file:
./scripts/restore.sh /backups/bugfinder-2025-05-14.tar.gz
```

### Step 3 — Verify
After restore, check:
```bash
docker-compose exec api node -e "
  const { MongoClient } = require('mongodb');
  MongoClient.connect(process.env.MONGO_URI).then(c => {
    return c.db().listCollections().toArray();
  }).then(cols => console.log('Collections:', cols.map(c => c.name)));
"
```

### Expected RTO breakdown
| Step | Time |
|------|------|
| Stop services | ~30s |
| Decompress backup | ~30–60s |
| mongorestore | ~3–8 min (depends on DB size) |
| Restart + health check | ~1 min |
| **Total** | **~5–10 min** |

---

## Service Recovery Procedures

### Backend API down

```bash
# Check logs
docker-compose logs api --tail=50

# Restart
docker-compose restart api

# Full redeploy
docker-compose up -d --force-recreate api
```

### MongoDB down

```bash
# Check status
docker-compose ps mongo
docker-compose logs mongo --tail=50

# Restart
docker-compose restart mongo

# Check replication lag (if replica set configured)
docker-compose exec mongo mongosh --eval "rs.status()"
```

### Redis down (sessions will be lost)

```bash
docker-compose restart redis
# Users will need to re-login — acceptable per SLA
```

---

## Security Incident Response

### Anomaly alert received

1. Check `anomaly_alerts` MongoDB collection for details
2. Review audit log: Admin Panel → Audit Log → filter by user
3. If account compromise suspected:
   - Lock account: `db.users.updateOne({ email: "..." }, { $set: { locked: true } })`
   - Invalidate sessions: delete from `sessions` collection
   - Notify user via email

### Bulk delete detected

1. Check which records were deleted from audit log
2. Restore from backup if accidental: `./scripts/restore.sh`
3. Re-apply any changes made after backup date manually

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `MONGO_URI` | Yes | MongoDB connection string |
| `SESSION_SECRET` | Yes | Express session secret (32+ chars) |
| `CREDENTIAL_VAULT_KEY` | Yes | AES-256 key for credential encryption |
| `VAULT_ADDR` | No | HashiCorp Vault address |
| `VAULT_TOKEN` | No | HashiCorp Vault token |
| `AWS_REGION` | No | AWS region for Secrets Manager |
| `AWS_SECRET_ARN` | No | AWS Secrets Manager ARN |
| `SAML_ENTRY_POINT` | No | SAML IdP SSO URL |
| `SAML_IDP_CERT` | No | SAML IdP signing certificate |
| `WEBAUTHN_RP_ID` | No | WebAuthn relying party domain |
| `WEBAUTHN_ORIGIN` | No | WebAuthn allowed origin |
| `MULTI_TENANT` | No | `true` to enable tenant isolation |
| `ADMIN_EMAIL` | Yes | Default admin email |
| `SMTP_HOST` | No | SMTP server for email alerts |

---

## Health Check Endpoints

| Endpoint | Expected Response |
|----------|------------------|
| `GET /health` | `{"status":"ok"}` |
| `GET /api/auth/me` | `401` if unauthenticated (server is up) |

---

## Contacts

| Role | Contact |
|------|---------|
| On-call engineer | Check PagerDuty |
| Security incidents | security@your-org.com |
| Database admin | dba@your-org.com |
