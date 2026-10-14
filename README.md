# V2Ray & Xray Subscription Hub

A self-hosted V2Ray/Xray subscription aggregator for Cloudflare Workers. It provides a password-protected web dashboard for managing proxy configurations and upstream subscription feeds, groups them in a chosen order, and publishes one combined subscription URL.

The project is a single Cloudflare Worker script (`worker.js`) with no npm runtime dependencies. Cloudflare Workers KV stores the group configuration, rotation setting, subscription token, and cached upstream configurations.

## 1. Deploy on Cloudflare

You need a Cloudflare account. These steps use the Cloudflare dashboard, so you do not need to install Node.js, Wrangler, or any local development tools.

### Step 1 — Set your dashboard password in the code first

Open `worker.js` in a text editor. At the very top, find:

```js
const DASHBOARD_PASSWORD = "CHANGE_ME_TO_YOUR_OWN_PASSWORD";
```

Replace the placeholder with a long, unique password of your own. Keep the quotation marks, and do not use the example placeholder as your real password.

**Important for a public GitHub repository:** never commit your real password. Keep the version in this public repository set to the placeholder. Make a private working copy of `worker.js`, change the password in that copy, and paste that private copy into the Cloudflare editor in Step 3. The password is hard-coded in the deployed script by this version of the project, so a person who can view the deployed source can read it. If you accidentally commit a real password, replace it immediately.

### Step 2 — Create a Cloudflare Worker

1. Sign in at [Cloudflare](https://dash.cloudflare.com/).
2. Select the account where you want to host the app.
3. Open **Workers & Pages**.
4. Choose **Create** or **Create application**, then choose **Create Worker**. The labels can vary slightly as Cloudflare updates its dashboard.
5. Enter a Worker name, for example `v2ray-subscription-hub`, and deploy the starter Worker.
6. Open the new Worker and choose **Edit code** (sometimes shown as **Quick edit**).
7. Replace the starter code with the entire contents of your private, password-edited `worker.js` copy.
8. Save and deploy the code.

Cloudflare will give the Worker a URL, usually on a `workers.dev` subdomain. Keep this URL: it is the address of your dashboard and subscription endpoint.

Official guide: [Create a Worker from the dashboard](https://developers.cloudflare.com/workers/get-started/dashboard/).

### Step 3 — Create a KV namespace

The Worker needs a KV namespace to persist your groups and settings.

1. In the Cloudflare dashboard, open **Workers KV** (it may appear under **Storage & databases**).
2. Choose **Create instance** or **Create namespace**.
3. Name it `VPN_DB`, then create it.

The namespace's display name is not technically required to be `VPN_DB`, but the **binding variable name must be exactly `VPN_DB`** because `worker.js` refers to that variable directly.

Official guide: [Get started with Workers KV](https://developers.cloudflare.com/kv/get-started/).

### Step 4 — Bind KV to your Worker

Creating a namespace alone is not enough; you must connect it to the Worker.

1. Open **Workers & Pages** and select your Worker.
2. Open **Settings** → **Bindings**.
3. Select **Add** / **Add binding**, then choose **KV namespace**.
4. Set **Variable name** to `VPN_DB` (match the spelling and capitalization exactly).
5. Select the namespace you created in Step 3.
6. Add the binding and deploy if Cloudflare prompts you to do so.

Official guide: [Bind a KV namespace to a Worker](https://developers.cloudflare.com/kv/concepts/kv-namespaces/).

### Step 5 — Open the dashboard

Visit your Worker URL. You should see the login page. Enter the password you set in Step 1.

If saving configuration fails, first check that the KV binding exists and its variable name is exactly `VPN_DB`.

## 2. Configure your subscriptions

### Create and manage server groups

Use **Add Server Group** to create a group. Give it a meaningful name such as `Germany`, `Finland`, or `Backup`. The order of groups matters: the rotation algorithm follows the order shown in the dashboard. You can drag groups to reorder them or use the up/down controls.

Each group can use one of two modes:

- **Direct Configs:** paste proxy URIs, one per line.
- **Subscription Links:** paste one or more upstream `https://` or `http://` subscription URLs, one per line.

When using subscription links, **Sync / Count** can fetch and inspect the current feed. **Save Changes** stores the group settings and attempts to refresh/cache subscription results. On VPN-client refresh, the Worker fetches upstream feeds again; if an upstream fetch fails or returns no usable configurations, it can use the group's previously cached configurations.

Only add subscription URLs that you trust. The Worker makes requests to these URLs from Cloudflare's infrastructure.

### Remove the placeholder configuration

The script contains an illustrative default entry so a new installation is not empty:

```text
vless://example-de-1@1.1.1.1:443?type=ws
```

This is a **dummy example**, not a working server. Replace it with your own configuration or delete the example group before relying on the subscription output.

### Choose the rotation chunk size

The default chunk size is `3`. The Worker takes up to that many configurations from the first group, then from the second group, and so on. It then repeats with the next chunk from each group until every available entry has been included.

For example, with a chunk size of `2` and groups A, B, and C, the output order is:

1. First 2 entries from A
2. First 2 entries from B
3. First 2 entries from C
4. Next 2 entries from A, then B, then C, continuing until the groups are exhausted

Use the preset buttons (`1`, `2`, `3`, `5`, or `10`) or enter a custom positive number. Save your changes to persist the setting.

### Save your changes

Click **Save changes** in the bottom bar after changing group names, group contents, group order, modes, or the rotation size. The dashboard also warns before leaving the page when it detects unsaved changes. `Ctrl+S` (or `Cmd+S` on macOS) triggers Save changes.

## 3. Copy the subscription link into your VPN client

The dashboard displays a protected URL similar to:

```text
https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/sub/123456
```

Use the exact URL displayed by your own dashboard; the domain and six-digit code above are examples only. Copy it into a V2Ray/Xray-compatible client that supports subscription URLs.

- The standard subscription response is Base64-encoded, which is commonly expected by subscription clients.
- To inspect the unencoded text in a browser, append `?format=plain` to the subscription URL. Use this only for troubleshooting; the normal client URL should omit this parameter.
- Select **New code** in the dashboard to regenerate the six-digit subscription token. The previous token stops working immediately, so update the URL in your VPN client afterward.

Do not post your subscription URL publicly. It is a bearer-style link: anyone who obtains it may be able to retrieve your subscription contents.

## 4. Supported configuration formats

The parser recognises these URI schemes: `vless`, `vmess`, `trojan`, `ss`, `ssr`, `hysteria2`, `hy2`, `hysteria`, `tuic`, `wireguard`, `wg`, `socks`, `socks5`, `anytls`, and `juicity`.

Upstream payloads can be plain-text URI lists or Base64-encoded URI lists. Wrapped configuration lines are stitched together when they look like continuation fragments.

The Worker attempts to rename output nodes to the pattern `Group Name - IP or host`. VMess remarks are updated in the decoded VMess payload; other supported URI types are renamed using the URI's fragment/host where the format can be parsed. Some unusual or vendor-specific formats may not be renamed perfectly.

## 5. Security notes and limitations

Please read these before exposing the Worker to the public internet.

- **The dashboard password is currently hard-coded.** Keep the real password out of a public Git repository. Anyone with source access to the deployed script can read it. A future improvement would be to move the password into a Cloudflare Worker secret/environment binding.
- **There is no login rate limiting in the supplied code.** Do not rely on this version as a high-security authentication service, especially for sensitive infrastructure.
- **The session cookie uses a SHA-256-derived token, not PBKDF2 or an HMAC-signed session.** The cookie is set with `HttpOnly`, `Secure`, and `SameSite=Strict` flags and a 30-day lifetime, but this should not be described as a PBKDF2 session system.
- **The subscription token is six digits.** It is convenient for sharing privately, but it has a limited search space and is not a substitute for strong authentication. Regenerate it if it is exposed and avoid publishing the link.
- The Worker fetches user-provided upstream subscription URLs. Add only URLs you trust and that you are authorised to use.
- Cloudflare Workers and KV have platform limits and plan-specific quotas. Check the current [Workers limits](https://developers.cloudflare.com/workers/platform/limits/) and [Workers KV documentation](https://developers.cloudflare.com/kv/) for the limits that apply to your account.

## 6. Troubleshooting

**The dashboard keeps asking for a password**

Make sure the password in the deployed `worker.js` is the password you are entering. If you redeploy the script with a different password, use that new password.

**Save changes fails or settings do not persist**

Confirm that the Worker has a KV namespace binding with the variable name `VPN_DB`. The namespace name and binding variable are separate things; it is the binding variable that must match the code.

**An upstream group shows no configurations**

Check that the upstream URL is reachable and returns a plain-text or Base64-encoded list of supported URI schemes. Try the dashboard's sync/count control and read any returned error. Some providers return a web page or require headers/authentication that this script does not support.

**My VPN client cannot import the subscription**

Use the normal URL without `?format=plain`. The Worker returns Base64 by default. Also verify that the subscription token is current and the client accepts the configuration schemes in the feed.

**The old subscription URL stopped working**

A new six-digit token was generated. Copy the latest subscription URL from the dashboard into your client.

## License and reuse

No license file is included because no license was specified. A public GitHub repository makes the code visible, but it does not automatically grant others permission to reuse, modify, or redistribute it. Choose and add a license before inviting others to reuse the project.

## 7. Official Cloudflare references

- [Workers dashboard deployment](https://developers.cloudflare.com/workers/get-started/dashboard/)
- [Workers KV getting started](https://developers.cloudflare.com/kv/get-started/)
- [KV namespace bindings](https://developers.cloudflare.com/kv/concepts/kv-namespaces/)
- [Workers platform limits](https://developers.cloudflare.com/workers/platform/limits/)

## Features

- **Round-robin chunk rotation:** interleaves entries from ordered server groups in configurable chunk sizes instead of exhausting one group before the next.
- **Mixed input per group:** manage direct proxy URIs or one or more upstream subscription URLs, and choose a different mode for each group.
- **Live upstream fetching with KV fallback:** refreshes upstream feeds when a client requests the subscription and uses cached entries when fetching fails or no usable entries are returned.
- **Plain-text and Base64 subscription output:** Base64 is the default for compatible clients; `?format=plain` is available for manual inspection.
- **Automatic node remarks:** attempts to label entries with their group name and IP/host, including VMess remark rewriting and IPv6 host normalisation for supported URI forms.
- **IPv4/IPv6 host parsing:** recognises bracketed IPv6 and normalises supported unbracketed IPv6 authorities to bracketed form.
- **Group ordering controls:** drag-and-drop reordering plus up/down controls for precise ordering.
- **Live dashboard counts and status:** displays group/configuration counts and subscription sync results in the interface.
- **Protected dashboard:** password-gated admin page with an `HttpOnly`, `Secure`, `SameSite=Strict` session cookie.
- **Regeneratable subscription token:** generate a new six-digit subscription URL code and invalidate the previous one.
- **Unsaved-change safeguards:** sticky save bar, unsaved-state indicator, before-leaving warning, and keyboard shortcut.
- **Single-file deployment:** the Worker and its HTML/CSS/JavaScript dashboard are contained in `worker.js`, with no npm runtime dependencies.