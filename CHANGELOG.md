# Changelog

## 0.7.5
### Fixed
- Direct-host logins now send the real `auraConfig.ConnectCSRFToken` as
  `aura.token` instead of the historical `"null"` fallback, matching the
  page contract used by Salesforce and preventing `KO: Errore Tecnico`
  after valid credentials.

## 0.7.4
### Fixed
- `loginUser` could still receive `KO: Errore Tecnico`: Aura action IDs
  are now unique and the bootstrap sequence is closer to the official app
  (`HostConfig.getConfigData`, then `PED_Login.init`, then `loginUser`),
  reusing the same page-scope ID across the three calls.

## 0.7.3
### Fixed
- The login flow now follows the official iOS app more closely: complete
  Safari/navigation and Aura AJAX headers, native app headers for the
  OAuth token exchange, the real Aura CSRF cookie in `loginUser` when the
  portal provides one, and the `PED_Login.init` call that the app sends
  before submitting credentials.
- `KO: Errore Tecnico` is now shown as an E-Distribuzione service error
  instead of "invalid email or password". Genuine credential refusals
  still show the normal invalid-credentials error.

## 0.7.2
### Fixed
- E-Distribuzione is now blocking the fallback host too, with a
  Salesforce "Transaction Security" rule (`app_blocked`). The block is
  now recognised as a temporary server-side block instead of a failed
  refresh: the integration shows a Repairs notice (not a credentials
  error), keeps the stored refresh token and retries on its own every
  hour.
- The portal's real login refusal text is now logged
  (`loginUser ha rifiutato l'accesso: '…'`): every refusal used to
  surface as "invalid email or password", even when the credentials
  were correct. A security-block refusal is reported as blocked access.

## 0.7.1
### Fixed
- Register export for production-only PODs (e.g. ITP… meters): the
  official `/reading` endpoint never publishes readings for them, so
  the export gave up before sending anything. A month is now exported
  as soon as ANY source has data — readings, GSE-TERNA measures or
  monthly TOU bands — and only PODs with nothing at all are retried
  the next day.

## 0.7.0
### Added
- Official GSE-TERNA measures in the register webhook payload: the
  integration opens the same Aura web session the portal uses
  (access token → `frontdoor.jsp` sid → `auraConfig` + CSRF cookie),
  selects the POD and queries
  `QueryRegulatoryComplianceStatusService`, returning the official
  D540/UPN/SSP rows — produced, fed-in and withdrawn energy per band
  plus file names and measure state — under `misure_gse_terna`.
- `fasce` in the payload: per-band (A1 fed-in / A2 withdrawn) monthly
  energy from `querymonthlytimeofuse`, so downstream sheets can fill
  the F1/F2/F3 columns directly.
- Login, token refresh and the new measures call now share one
  primary-host → `*.my.site.com` fallback wrapper: every request that
  hits the Imperva block is retried transparently.

## 0.6.2
### Fixed
- The register export window for the end-of-month reading is wider: it now
  covers from the last day of the month to mid-next-month. Different
  meters publish their official reading at different times (the exchange
  meter on the 1st; the production meter may arrive days later, or be
  dated at the month's last day) — a 7-day window at the start of the
  following month could report "readings not published" for a perfectly
  fine month.

## 0.6.1
### Fixed
- Readings register export fetched the wrong month's reading: E-Distribuzione
  dates the official monthly reading at the 1st of the *following* month
  (verified on a real response — `measureTs` 2026-09-01 with source file
  `_202608_`, i.e. the September-1st reading *closes* August). Exporting
  month M now requests the reading measured at the start of M+1, with a
  few days of slack. For the sheet's "letture fine mese" this is the right
  cumulative value.
- `righe` in the webhook payload now also flattens `publishedPowerPeaks`
  (POT slots per band), instead of leaving them nested — and no longer
  repeats the whole peaks array inside every row.

## 0.6.0
### Added
- Monthly export of E-Distribuzione's official meter readings to an
  external webhook (e.g. a self-hosted n8n instance mapping them onto a
  pre-formatted Google Sheet) — meant for the meter readings register
  ("registro delle letture") that electric workshops (PV plants above
  20 kW with self-consumption) must keep for the Italian customs agency
  (ADM, Circolare 27/2025 allows the electronic format).
  - New "Readings register (webhook)" option in the integration options:
    webhook URL (empty = disabled) plus an optional secret sent as
    `Authorization: Bearer` (n8n "Header Auth").
  - Automatic export: at the start of each month the previous month's
    official readings (`/reading` endpoint: cumulative EA/ER per time band
    plus power peaks) are POSTed to the webhook as soon as they are
    published — one attempt per day per POD until they arrive, per-POD
    progress persisted across restarts. Webhook failures never break the
    data update cycle.
  - New `edistribuzione.esporta_registro` action (device + month YYYY-MM)
    to export a chosen month on demand — for backfilling past months.
  - Payload sent per POD: raw `letture` array plus a flattened `righe`
    view (one row per published slot, for n8n Split Out nodes) with POD,
    meter role, month and period metadata.

## 0.5.4
### Fixed
- An account with an expired password used to fail the setup with the
  generic "OTP exchange failed" abort: credentials and OTP were accepted,
  but the portal answered with its password-renewal form instead of the
  OAuth redirect. The form is now recognised and reported as "password
  expired, renew it on the official site or app" — both during login and
  at OTP submission.

## 0.5.3
### Fixed
- Login and token refresh no longer hit E-Distribuzione's anti-bot check
  ("Pardon Our Interruption", Imperva). Requests now go through
  `edistribuzione.my.site.com` — the same Salesforce org and the same
  PortaleClienti community, on the canonical Salesforce domain without
  Imperva in front — instead of `private.e-distribuzione.it`. Absolute URLs
  that the portal generates on the protected domain (frontdoor.jsp, the JS
  redirect to the OTP form, meta Location, form actions) are rewritten to
  the direct domain before being followed. No changes needed to existing
  entries: the fix also applies to refresh, so a configured integration
  recovers on its own at the next update cycle.

## 0.5.2
### Changed
- *Report issue* in Home Assistant now opens this repository's issues, instead of the original
  repository's.

## 0.5.1
### Fixed
- Once ignored, the notice about E-Distribuzione blocking automated access stayed hidden even
  after reloading the integration while the block lasted. It now shows again after every
  reload or restart as long as access is blocked, and disappears when the integration is
  removed.

## 0.5.0
First release of this fork of
[maurobraggio/HomeAssistant-EDistribuzione](https://github.com/maurobraggio/HomeAssistant-EDistribuzione).

### Added
- F1 / F2 / F3 time bands: three more statistics for the consumption direction
  (`edistribuzione:<pod>_energia_f1`, `_f2`, `_f3`), calculated from the 15-minute samples
  with the ARERA holiday calendar (October 4 included from 2026). Hour by hour they add up to
  the total, cover all the history already downloaded and follow corrections on their own.
- *POD card* (`custom:edistribuzione-pod-card`): consumption, return to grid and the F1/F2/F3
  split in day, week, month and year views, with Home Assistant's own look in light and dark
  mode. The integration loads it by itself, with no resource to add.
- Italian and English translations: entity names, setup and options, actions and error
  messages follow each user's language.
- Integration icon in Home Assistant, from version 2026.3.
- A notice in *Settings > Repairs* when E-Distribuzione blocks automated access with its
  anti-bot check; it disappears on its own once access works again.

### Changed
- README in English, with a step-by-step guide to setup, history import and checks.

### Fixed
- Sensors missing until a restart when E-Distribuzione did not answer while Home Assistant
  was starting.
- When E-Distribuzione answers with its anti-bot check, setup no longer fails with the generic
  "cannot connect" error and updates no longer log an unexpected error: the integration
  reports the block and retries once an hour.
