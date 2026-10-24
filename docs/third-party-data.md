# Third-party data

## Common-password block list

Used by `IPasswordPolicy` (T06) to reject common or breached passwords. Matching is case-insensitive.

| | |
|---|---|
| File in repo | `backend/src/Auth.Services/Passwords/common-passwords.txt` (embedded resource `Auth.Services.Passwords.common-passwords.txt`) |
| Contents | Top 100,000 passwords of the "10 million passwords" dataset, one per line, ASCII. 96,518 entries are unique when case is ignored. |
| Upstream file | `Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt` in [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) |
| Pinned revision | SecLists commit `a61e8f503c54bf3c399b8f9e4da97e7059a8437e` (master on 2026-10-24); the file last changed in commit `c205c36a445bff37f8e58a9ec829105cd4975c58` |
| SHA-256 | `1472aafa2561df5e3293aee252aee3ca660c12b399a283cf808bb01b39be388b` (781,879 bytes) |
| License | SecLists is distributed under the **MIT License** (Copyright (c) 2018 Daniel Miessler). The underlying dataset was published by Mark Burnett (xato.net, 2015) for security research. Please confirm the upstream terms before redistributing the list outside this project. |

The file is stored byte for byte (`-text` in `.gitattributes`), so the SHA-256 above can be checked on any clone:

```
sha256sum backend/src/Auth.Services/Passwords/common-passwords.txt
```

### Updating the list

1. Download the new file from SecLists at a pinned commit, not `master`.
2. Replace `common-passwords.txt`, then update the revision, SHA-256 and entry count above.
3. Run the unit tests; `PasswordPolicyTests.Bundled_list_is_loaded_with_about_100k_entries` checks the size.

### Notes

- With a 12-character minimum, only a few hundred entries are long enough to matter on their own, but the whole list is kept as specified. The optional online HIBP k-anonymity check (A9) is out of scope for T06.
