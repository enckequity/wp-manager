---
name: wp-manager
description: Use when managing WordPress sites (updates, health, posts, pages) via wp_* tools.
version: 0.1.4
metadata:
  hermes:
    tags: [wordpress, updates, content, websites]
---

# WordPress sites with wp-manager

The `wp_*` tools manage WordPress sites that run the **TeamShift Connector**
plugin. They cover plugin/theme/core/translation updates (with a health check after every run) and
creating or editing posts and pages. wp-manager takes **no backups**.

## Connecting a site

1. On the WordPress site: install and activate *TeamShift Connector*, open
   **Tools → TeamShift Connector**, click **Create connection for TeamShift** and copy the `wpmh1:…` string.
2. The Application Password is never taken from chat and never stored by wp-manager. Ask the user
   to save the connection string (or the bare Application Password) as the workspace secret
   `WPM_<SITE_ID>_APP_PASSWORD` (the site id is derived from
   the address, e.g. `WPM_MYSITE_APP_PASSWORD` for mysite.com). If they paste the connection
   string or a password into chat, do not repeat any part of it back; ask them to save it as that
   secret instead. 1Password (`op://`) references are not supported.
3. Then call `wp_site_add` with `url` and `username` (or the connection string, whose password
   is ignored), `storage: existing` and `credential: {"env": "WPM_<SITE_ID>_APP_PASSWORD"}`.
   Every `wp_site_add` asks the user to approve the URL and the secret it will receive. Ids that
   would share another site's secret name (`my-blog` vs `my--blog`) are refused: pick a clearly
   different id.
4. `http://` sites are refused unless the user explicitly accepts `allow_insecure: true` (its own
   approval prompt). Localhost is fine.

## Updates

1. `wp_updates_scan` (add `refresh: true` to make WordPress re-check wordpress.org). Summarise what
   is pending per site. Point out major core versions, incompatible items and premium plugins
   without a package.
2. **Before any update, ask whether the user has a recent backup from their host.** wp-manager
   takes none.
3. `wp_update_apply` with one `type` per call (`plugin`, `theme`, `core`, `translations`). It is
   approval-gated: the user is asked first. Prefer explicit `items`. On several sites, go one site
   at a time and stop at the first unhealthy result.
4. Read the result. If it has an `alert` (health degraded or down) or `warning` (some items
   failed), say so first, plainly, with the failing signals. Never call that run a success. Tell
   the user to check the site and restore from backup if it is broken.
5. `wp_health_check` checks a site on demand: home page, REST API, connector self-report.

## Content

- Always `wp_content_get` before editing, and edit the returned `content`. Keep its structure
  intact.
- `editor: "blocks"`: write Gutenberg block markup (`<!-- wp:paragraph --><p>…</p><!-- /wp:paragraph -->`,
  `wp:heading`, `wp:list`, `wp:image`, …). Keep existing blocks and their attributes. Do not
  flatten them to plain HTML.
- `editor: "classic"`: HTML is fine.
- `editor: "page_builder"` (Elementor, Divi, WPBakery, Beaver Builder, …): the raw content is not
  what renders. Tell the user to edit it in wp-admin. Only change title/excerpt/slug here. Set
  `confirm_page_builder: true` for a body edit only if they explicitly insist after the warning.
  Advanced Custom Fields and similar meta-driven pages behave the same way.
- New posts and pages are saved as **drafts** by default. Publishing, or editing anything already
  published, needs the user's approval. Do not set `status: publish` unless the
  user asked for it. Share the draft link or suggest a preview in wp-admin.

## Safety notes

- Never ask the user to type their WordPress admin password. wp-manager only uses Application
  Passwords, which can be revoked under Users → Profile → Application Passwords.
- Every update, content save (drafts included), site add and site remove asks the user first, and
  unattended runs (cron) cannot do any of them. This cannot be turned off. Scans and health checks
  are fine in cron.
- Every write action is logged to `wp-manager/actions.jsonl` in the workspace home.
