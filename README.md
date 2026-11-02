# SubScope – subdomain finder

Next.js 14 + Tailwind CSS. Finds subdomains from public sources, checks which ones respond, and exports the list.

## Run

    npm install
    npm run dev        # http://localhost:3000
    npm run build && npm start

## Data sources

crt.sh, HackerTarget, AlienVault OTX and Anubis work without keys.
Optional extra sources (set in `.env.local`):

    VIRUSTOTAL_API_KEY=...
    SECURITYTRAILS_API_KEY=...

## Notes

- `GET /api/subdomains?domain=example.com` returns the discovered hostnames.
- `POST /api/probe` with `{ "hosts": [...] }` (max 12) resolves each host and reads status, IP and server headers.
  It refuses private, loopback and link-local addresses.
- Use live checks only on domains you own or are authorized to test.
