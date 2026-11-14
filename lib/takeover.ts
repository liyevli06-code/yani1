/**
 * A small, well-known set of "dangling CNAME" signatures: a subdomain's CNAME still points at
 * a third-party platform, but the resource on that platform (the S3 bucket, the Heroku app,
 * the GitHub Pages site…) is gone or was never claimed. If someone else can register that
 * resource name on the same platform, they can serve content under the victim's subdomain —
 * the classic "subdomain takeover". This only reads the CNAME record and the same unauthenticated
 * page we already fetch; nothing is registered, claimed, or otherwise acted on.
 */
export type TakeoverSignature = { service: string; cnameContains: string; bodyContains: string[] };

export const TAKEOVER_SIGNATURES: TakeoverSignature[] = [
  { service: "GitHub Pages", cnameContains: "github.io", bodyContains: ["there isn't a github pages site here"] },
  { service: "Heroku", cnameContains: "herokuapp.com", bodyContains: ["no such app", "there's nothing here, yet"] },
  { service: "Amazon S3", cnameContains: "s3", bodyContains: ["nosuchbucket", "the specified bucket does not exist"] },
  { service: "Azure", cnameContains: "azurewebsites.net", bodyContains: ["404 web site not found", "error 404 - web app not found"] },
  { service: "Azure Traffic Manager", cnameContains: "trafficmanager.net", bodyContains: ["404 web site not found"] },
  { service: "Shopify", cnameContains: "myshopify.com", bodyContains: ["sorry, this shop is currently unavailable"] },
  { service: "Fastly", cnameContains: "fastly.net", bodyContains: ["fastly error: unknown domain"] },
  { service: "Surge.sh", cnameContains: "surge.sh", bodyContains: ["project not found"] },
  { service: "Bitbucket", cnameContains: "bitbucket.io", bodyContains: ["repository not found"] },
  { service: "Pantheon", cnameContains: "pantheonsite.io", bodyContains: ["404 error unknown site"] },
  { service: "Readme.io", cnameContains: "readme.io", bodyContains: ["project doesnt exist"] },
  { service: "Webflow", cnameContains: "webflow.io", bodyContains: ["the page you are looking for doesn't exist"] },
  { service: "Zendesk", cnameContains: "zendesk.com", bodyContains: ["help center closed"] },
  { service: "Statuspage", cnameContains: "statuspage.io", bodyContains: ["you are being redirected"] },
  { service: "Ngrok", cnameContains: "ngrok.io", bodyContains: ["tunnel", "not found"] },
  { service: "Netlify", cnameContains: "netlify.app", bodyContains: ["not found - request id"] },
  { service: "Cargo", cnameContains: "cargo.site", bodyContains: ["if you're moving your domain"] },
  { service: "Unbounce", cnameContains: "unbouncepages.com", bodyContains: ["the requested url was not found on this server"] },
  { service: "UserVoice", cnameContains: "uservoice.com", bodyContains: ["this uservoice subdomain is currently available"] },
  { service: "Help Scout", cnameContains: "helpscoutdocs.com", bodyContains: ["no settings were found for this company"] },
];

export type TakeoverFinding = { vulnerable: boolean; service: string | null; cname: string | null };

/**
 * `cname` is the resolved CNAME target (if any). `body`/`requestFailed` describe the result of
 * the one request the live probe already makes. A match requires the CNAME to point at a known
 * platform AND (the page to carry that platform's own "nothing here" text, or the request to
 * fail outright) — pointing at a platform you're actively using is normal and not flagged.
 */
export function detectTakeover(cname: string | null, body: string, requestFailed: boolean): TakeoverFinding {
  if (!cname) return { vulnerable: false, service: null, cname: null };
  const lowerCname = cname.toLowerCase();
  const lowerBody = body.toLowerCase();
  for (const sig of TAKEOVER_SIGNATURES) {
    if (!lowerCname.includes(sig.cnameContains)) continue;
    const bodyMatches = sig.bodyContains.some((s) => lowerBody.includes(s));
    if (bodyMatches || (requestFailed && lowerBody.length === 0)) {
      return { vulnerable: true, service: sig.service, cname };
    }
  }
  return { vulnerable: false, service: null, cname };
}
