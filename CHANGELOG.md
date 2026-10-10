# Changelog

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
