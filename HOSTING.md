# V&CO OFFICE phone setup

Status: hosting files prepared, not deployed. The APK alone cannot provide shared accounts. 10.0.2.2:8080 is an Android emulator address and cannot connect a physical phone to your computer.

1. Create a private GitHub repository and upload only the contents of this hosting folder. It includes no local database, passwords, photos, OAuth tokens or signing keys.
2. Sign in at https://dashboard.render.com, connect that repository, select New > Blueprint and use render.yaml. Review the paid service and 1 GB persistent disk charges shown before confirming. A free service cannot preserve this SQLite database. Singapore is the configured region.
3. Set ADMIN_EMAIL to your administrator email and ADMIN_PASSWORD to a new private password of 12–128 characters. These bootstrap the first administrator on a new disk. Keep the generated DRIVE_BACKUP_PASSWORD separately in a password manager for recovery.
4. Deploy, then open the assigned https://...onrender.com/health URL. It must return status ok. Use the actual assigned URL, not an invented example. This is a fresh office database; local demo records are not transferred.
5. On your phone, open Office connection and save the base HTTPS URL without /health. Sign in with the administrator credentials from step 3. Employees and additional administrators can register; approve their applications from More > Registrations.
6. For Google Drive, create a Google Web OAuth client with the exact https://YOUR-ASSIGNED-HOST/api/drive/callback redirect. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI in Render environment settings, redeploy, then authorize staffvandco@gmail.com from More > Google Drive. Do not replace the recovery password after backups have started.

Keep a single backend instance with its /data persistent disk. That disk contains both SQLite and the photo encryption key. Monitor disk use and increase capacity as photos accumulate. Drive backups remain inactive until OAuth configuration and consent are complete.

The service configuration has been prepared from Render documentation; a real Docker deployment and phone connection still need verification after account setup. No hosting charge has been incurred by this preparation.

References: https://render.com/docs/disks and https://render.com/docs/blueprint-spec
