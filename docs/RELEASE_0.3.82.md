# Kaevo plugin 0.3.82

Adds the deletion eligibility and cleanup delivery capabilities required by Kaevo Cloud. Eligibility checks validate the exact planned profile and Jellyfin-user bindings and reject removal of the last user or administrator. Signed cleanup delivery supports an already-authorized account-deletion operation after normal account access is frozen.

The existing two-way profile deletion setting remains unchanged. Installing this update does not enable deletion or delete any account.

Validation: 879 plugin tests, 97 Cloud emulator tests, and 29 iOS tests passed. Package dependencies verified. Live account deletion remains pending a separate authorized device test.

Update through the existing Jellyfin plugin catalog, restart Jellyfin, then confirm version 0.3.82.0 on the plugin page.
