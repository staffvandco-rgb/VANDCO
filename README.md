# V&CO OFFICE PostgreSQL migration — READY FOR CUTOVER

This is a separate staging backend. The current Render application and D:\SAF backend have not been replaced.

The Supabase TLS connection, private storage bucket, full integration suite, restart persistence, and production import are complete. The existing Render service has not been replaced yet.

## Design

- PostgreSQL tables live in the private office_app schema, outside the exposed public API schema; access is revoked for anon/authenticated/PUBLIC.
- Business transactions use one PostgreSQL connection and a schema-specific transaction lock to prevent duplicate attendance, registration decisions, and recurring tasks.
- Photos are encrypted with AES-GCM and held in the private Supabase bucket. The existing backend enforces employee/admin access before downloading them.
- OFFICE_ENCRYPTION_KEY is stable across deployments. Never regenerate it for an existing database. Its local copy is in ../.office-secrets/encryption-key.txt.
- Database passwords, storage secret keys, and private recovery credentials remain outside this folder, in the Git-ignored, restricted .office-secrets folder.
- Imported API exports do NOT contain passwords, internal audit data, other employees' notifications, or unreferenced photos. Unique new account passwords are written privately by the importer; administrators must distribute them privately and employees should change them in the app.
- Google Drive OAuth state now lives in PostgreSQL, but real Google consent/backup/restore still needs verification. Version 2 encrypted backups need a PostgreSQL-aware restore tool; the old SQLite restore script must not be used.
- Render Free still sleeps; this storage change does not provide guaranteed 10:15 delivery or closed-app push notifications.

## Remaining verification and cutover

1. In Render, set PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD, SUPABASE_URL, SUPABASE_SECRET_KEY, PHOTO_BUCKET, OFFICE_ENCRYPTION_KEY, OFFICE_DB_SCHEMA, HOST, OFFICE_TIMEZONE. Include `supabase-ca.crt` with the source and keep the existing HTTPS URL.
2. Deploy the reviewed backend and verify the Android app connects. Keep the rescue export and the private generated password list.
3. Configure and test Google Drive backups afterward.

Supabase settings are loaded from ../.office-secrets/supabase.json for local tests. Render uses environment variables. No secrets belong in the APK.
