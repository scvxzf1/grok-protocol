# Private inputs (do not commit real data)

Put **your own** mail pools and proxy lists here. Real files are gitignored.

| Example file | Purpose |
| --- | --- |
| `outlook_mail.example.txt` | Outlook/Hotmail OAuth mail pool format |
| `proxies.example.txt` | Residential / sticky proxy pool format |

## Quick start

```bash
# from repo root
cp need/proxies.example.txt proxies.txt
# edit proxies.txt with real lines

cp need/outlook_mail.example.txt need/my_outlook.txt
# edit need/my_outlook.txt with real accounts
```

Never share:

- refresh tokens / mailbox passwords
- proxy `user:pass` lines
- generated `accounts_*.txt` / `xai_credentials/`
