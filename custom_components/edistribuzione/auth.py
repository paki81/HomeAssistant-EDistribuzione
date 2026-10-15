"""Client di autenticazione per E-Distribuzione (Salesforce Experience Cloud).

Il portale risponde su due hostname della stessa org Salesforce: quello
"custom" (private.e-distribuzione.it) e' il dominio ufficiale ma sta dietro
Imperva, che da ottobre 2026 blocca i client non-browser; il dominio
canonico *.my.site.com e' la stessa org/community servita dalla CDN di
Salesforce senza antibot. Login e refresh partono SEMPRE dall'host primario
e ripiegano sul diretto solo se arriva la pagina di verifica, cosi'
l'integrazione torna da sola al dominio ufficiale quando Enel togliera' il
blocco. Dettagli in const.py.

Login OAuth2 Authorization Code + PKCE standard, ma la parte difficile sta nel
mezzo: le credenziali si sottomettono via un'azione Aura (Salesforce
Lightning), e l'OTP passa da una classica pagina Visualforce "Login Flow"
(ViewState/RichFaces). Sono dettagli di implementazione della UI, non un'API
pubblica stabile: questo modulo scrapa HTML/JSON con regex, e SI ROMPERA' se
Enel cambia il template Experience Cloud o la versione di RichFaces. I punti
più fragili sono le funzioni statiche di scraping in fondo al file - il primo
posto da controllare se il login inizia a fallire.

Una volta ottenuto un refresh_token, questa fragilità non serve più:
AuthClient.async_refresh_access_token() parla solo con l'endpoint OAuth2
standard.

async_begin_login esegue in sequenza:
    1. _carica_pagina_login       GET /oauth2/authorize (PKCE) -> pagina di login
    2. _invia_credenziali         POST Aura loginUser -> URL di frontdoor.jsp
    3. _segui_a_pagina_otp        GET frontdoor -> bridge JS -> pagina OTP
    4. _async_avvia_invio_otp     submit vuoto: fa DAVVERO partire l'invio dell'OTP

async_submit_otp esegue poi:
    5. _sottometti_codice_otp          POST del form con l'OTP -> meta Location
    6. _scarica_pagina_dopo_otp        segue quel redirect
    7. _estrai_codice_autorizzazione   trova code/state (gestendo il consenso
                                        OAuth alla primissima autorizzazione)
    8. _async_exchange_code            POST /oauth2/token
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import html as html_lib
import json
import logging
import re
import secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import aiohttp

from .const import (
    AURA_ENDPOINT,
    GSE_TERNA_PAGE_URL,
    LOGINFLOW_URL,
    OAUTH_AUTHORIZE_URL,
    OAUTH_CLIENT_ID,
    OAUTH_REDIRECT_URI,
    OAUTH_SCOPE,
    OAUTH_TOKEN_URL,
    SF_FRONTDOOR_URL,
    SF_HOST_DIRETTO,
    SF_HOST_PRINCIPALE,
    SF_HOSTS,
)

_LOGGER = logging.getLogger(__name__)

# La webview dell'app iOS usa uno UA Safari completo. La forma abbreviata
# usata fin qui ("... AppleWebKit/605.1.15") veniva classificata da Imperva
# come traffico automatico già alla pagina di login.
_MOBILE_USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 "
    "Mobile/15E148 Safari/604.1"
)
# Le chiamate native dell'app (token/userinfo) non passano dalla webview e
# usano invece lo UA CFNetwork osservato nella stessa cattura.
_APP_USER_AGENT = "e-Distribuzione/1 CFNetwork/3896.200.41 Darwin/27.2.0"
_MOBILE_ACCEPT_HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_MOBILE_ACCEPT_LANGUAGE = "it-IT,it;q=0.9"


def _headers_navigazione(sec_fetch_site: str = "none") -> dict[str, str]:
    """Header delle navigazioni nella webview dell'app iOS."""
    return {
        "User-Agent": _MOBILE_USER_AGENT,
        "Accept": _MOBILE_ACCEPT_HTML,
        "Accept-Language": _MOBILE_ACCEPT_LANGUAGE,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": sec_fetch_site,
    }


def _headers_ajax() -> dict[str, str]:
    """Header delle POST Aura/JSF originate dalla pagina già caricata."""
    return {
        "User-Agent": _MOBILE_USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": _MOBILE_ACCEPT_LANGUAGE,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }


def _headers_app() -> dict[str, str]:
    """Header delle chiamate native dell'app (fuori dalla webview)."""
    return {
        "User-Agent": _APP_USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": _MOBILE_ACCEPT_LANGUAGE,
    }


# Le chiamate Aura delle pagine del portale arrivano da un browser desktop:
# lo stesso UA usato nella cattura in cui è stata verificata la pipeline.
_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

_MAX_REDIRECT_HOPS = 15

# Nomi di campo di fallback del form RichFaces del login flow, usati solo se
# _analizza_pagina_otp non riesce a scoprirli dinamicamente dalla pagina reale
# (i prefissi "thePage:j_id2:..." sono generati da Salesforce e possono
# cambiare tra deploy).
_CAMPO_OTP_INPUT_DEFAULT = "thePage:j_id2:i:f:pb:d:element___input____OTP_Input"
_CAMPO_RICHIEDI_NUOVO_OTP_DEFAULT = "thePage:j_id2:i:f:pb:d:element___hidden____Richiedi_nuovo_OTP"
_CAMPO_NEXT_AJAX_DEFAULT = "thePage:j_id2:i:f:pb:pbb:nextAjax"

# Frammenti con cui il portale segnala che l'account ha troppe sessioni
# aperte contemporaneamente ("Hai superato il numero di sessioni simultanee
# consentite", osservato sul sito reale). Va distinto da credenziali sbagliate
# e da un cambio di markup: in questo stato il login non prosegue e l'OTP non
# viene nemmeno inviato, quindi l'utente resterebbe ad aspettare un codice che
# non arriva.
_MARCATORI_TROPPE_SESSIONI = (
    "sessioni simultanee",
    "sessioni contemporanee",
    "numero di sessioni",
    "sessioni consentite",
)

# Pagine della protezione antibot di Imperva (Incapsula), che risponde al
# posto di login e token endpoint quando classifica il traffico come
# automatico: la verifica JavaScript "Pardon Our Interruption" (osservata
# l'8 ottobre 2026, status 200) e il blocco "Incapsula incident ID". Solo
# marcatori di queste due pagine: lo script _Incapsula_Resource può
# comparire anche nelle pagine normali di un sito protetto.
_MARCATORI_ANTIBOT = (
    "pardon our interruption",
    "incapsula incident id",
)

# Regola "Transaction Security" di Salesforce che blocca l'app OAuth
# sull'host diretto (osservata il 12 ottobre 2026 sul token endpoint:
# 400 {"error":"app_blocked","error_description":"this app is blocked by
# Transaction Security"}). Il refresh_token e' valido - un token scaduto
# risponde invalid_grant - quindi e' un blocco lato server, non un problema
# di credenziali.
_MARCATORI_BLOCCO_SICUREZZA = (
    '"app_blocked"',
    "blocked by transaction security",
)

# Form "cambio password" che il portale impone quando la password
# dell'account e' scaduta: credenziali e OTP vengono accettati lo stesso,
# ma al posto del redirect OAuth arriva la pagina di rinnovo (Visualforce,
# campi tipo *newPassword*). Va distinta dagli errori di parsing: la cura e'
# cambiare la password sul sito/app ufficiale, non ritentare il login.
_MARCATORI_PASSWORD_SCADUTA = (
    "password scaduta",
    "cambia la password",
    "cambiare la password",
    "modifica la password",
    "changepassword",
    "newpassword",
    "nuovapassword",
)

# Testo con cui la risposta al primo submit del form conferma di avere
# spedito il codice (confermato su HAR reale: "Abbiamo inviato un codice a 5
# cifre al tuo indirizzo email"). Più varianti perché il canale (email/SMS) e
# la formulazione cambiano da account ad account: l'assenza di conferma NON
# viene trattata come errore fatale (romperebbe login altrimenti validi con
# una formulazione diversa), solo segnalata.
_MARCATORI_OTP_INVIATO = (
    "abbiamo inviato",
    "inviato un codice",
    "codice a 5 cifre",
    "codice è stato inviato",
    "nuovo codice",
)

# Etichette del pulsante che APPROVA sulla schermata di consenso OAuth. Sulla
# pagina reale i due pulsanti hanno lo STESSO name="save" e si distinguono
# solo per il valore: "Consenti" approva, " Nega " (con gli spazi) rifiuta -
# sbagliare pulsante significa negare l'autorizzazione all'integrazione,
# quindi il valore va confrontato per intero, non cercato come sottostringa.
_ETICHETTE_CONSENSO = ("consenti", "allow", "approve", "autorizza", "accetta")

# Il redirect verso l'app così come lo mostra il browser: da solo, o dentro la
# riga che Chrome/Edge scrive nella Console sviluppatori ("Failed to launch
# 'eneldist://redirect#access_token=...' because the scheme does not have a
# registered handler."), virgolette incluse.
_RE_REDIRECT_APP = re.compile(re.escape(OAUTH_REDIRECT_URI) + r"[^\s'\"<>]*")


def _parametri_redirect(url: str) -> dict[str, str]:
    """Parametri del redirect dell'app, dal fragment (user-agent flow) o
    dalla query.

    Decodificati con unquote, non come form (parse_qs): un '+' in un token è
    un più letterale, e trasformato in spazio darebbe un token che sembra
    valido ma viene rifiutato.
    """
    parti = urlsplit(url)
    parametri: dict[str, str] = {}
    for coppia in (parti.fragment or parti.query).split("&"):
        chiave, _, valore = coppia.partition("=")
        if chiave:
            parametri[unquote(chiave)] = unquote(valore)
    return parametri


def _contiene(testo: str, marcatori: tuple[str, ...]) -> bool:
    minuscolo = testo.lower()
    return any(marcatore in minuscolo for marcatore in marcatori)


def _scrivi_pagina_debug(html: str, nome_file: str) -> None:
    try:
        percorso = Path(nome_file)
        percorso.write_text(html, encoding="utf-8")
    except OSError as exc:
        _LOGGER.debug("Impossibile salvare %s su disco: %s", nome_file, exc)
        return
    _LOGGER.error("Pagina completa salvata in %s", percorso.resolve())


def _salva_pagina_debug(html: str, nome_file: str) -> None:
    """Scrive la pagina su disco (best-effort) e ne logga il percorso, così è
    richiedibile in una segnalazione senza dover far catturare una HAR.

    La scrittura è delegata a un executor quando siamo dentro l'event loop di
    Home Assistant, che segnala l'I/O sincrono come "blocking call". Fuori da
    un event loop (test, scripts/verify_login.py) scrive direttamente.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _scrivi_pagina_debug(html, nome_file)
        return
    # Deliberatamente non atteso: è un dump diagnostico best-effort, non deve
    # rallentare né far fallire il login se il disco è lento o pieno.
    loop.run_in_executor(None, _scrivi_pagina_debug, html, nome_file)


def _log_parsing_failure_context(html: str, campo_cercato: str) -> None:
    """Logga titolo + anteprima della pagina quando un campo atteso non si
    trova - distingue "regex sbagliato" (il campo c'è ma in forma diversa) da
    "pagina completamente diversa da quella attesa" senza dover chiedere
    un'altra cattura per scoprirlo. Salva anche la pagina intera su disco."""
    title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else "(nessun <title> trovato)"
    _LOGGER.error(
        "Campo '%s' non trovato. Titolo pagina: %r. Lunghezza: %d caratteri. "
        "Primi 300 caratteri: %r",
        campo_cercato,
        title,
        len(html),
        html[:300],
    )
    _salva_pagina_debug(html, "otp_page_debug.html")


class AuthError(Exception):
    """Errore generico di autenticazione."""


class InvalidCredentials(AuthError):
    """Email o password errate."""


class InvalidOtp(AuthError):
    """Codice OTP errato o scaduto."""


class TroppeSessioni(AuthError):
    """L'account ha già troppe sessioni aperte: il portale rifiuta il login
    prima di inviare qualunque OTP.

    Non è un problema di credenziali né di markup cambiato: finché le altre
    sessioni non vengono chiuse o non scadono (app ufficiale, sito, tentativi
    precedenti di questa stessa integrazione) non c'è niente da reinserire
    nel form, va liberata una sessione e riprovato.
    """


class AccessoBloccato(AuthError):
    """E-Distribuzione ha risposto con la pagina antibot di Imperva invece
    che con quella attesa: l'accesso automatico è bloccato lato server.

    Non è un problema di credenziali né di markup cambiato, e qui non c'è
    niente da correggere: va segnalato in modo chiaro e riprovato più tardi,
    senza insistere.
    """


class ErroreServizio(AuthError):
    """E-Distribuzione ha risposto con un errore tecnico del portale.

    Esempio osservato: 'KO: Errore Tecnico'. Non e' una prova che email o
    password siano sbagliate e non indica da solo un blocco antibot o
    Transaction Security: va mostrato come problema del servizio.
    """


class PasswordScaduta(AuthError):
    """Il portale ha risposto con il form di cambio password: credenziali e
    OTP sono stati accettati, ma la password dell'account e' scaduta.

    Il login non puo' completarsi da qui: la password va rinnovata sul sito
    o sull'app ufficiale, poi si riprova da capo.
    """


class LoginBrowserError(AuthError):
    """L'URL incollato dal browser non è il redirect OAuth atteso.

    Attributo 'motivo': 'url' (non contiene eneldist://redirect, oppure
    mancano i token/code) oppure 'state' (il redirect appartiene a un'altra
    sessione di login: va rifatto l'accesso con l'URL mostrato, che rigenera
    lo state a ogni step).
    """

    def __init__(self, motivo: str, msg: str = "") -> None:
        super().__init__(msg or motivo)
        self.motivo = motivo


class CodiceNonValido(AuthError):
    """Lo scambio dell'authorization code o l'autorizzazione nel browser è
    stata rifiutata (invalid_grant, access_denied e simili): va rifatto il
    login nel browser e incollato il redirect appena generato."""


def _verifica_non_password_scaduta(testo: str) -> None:
    """Alza PasswordScaduta se la risposta e' il form di cambio password."""
    if _contiene(testo, _MARCATORI_PASSWORD_SCADUTA):
        raise PasswordScaduta("E-Distribuzione richiede il cambio della password scaduta")


def _verifica_non_bloccato(testo: str) -> None:
    """Alza AccessoBloccato se la risposta è la pagina antibot o il blocco
    Transaction Security dell'app."""
    if _contiene(testo, _MARCATORI_ANTIBOT):
        raise AccessoBloccato("E-Distribuzione ha risposto con la pagina antibot (Imperva)")
    if _contiene(testo, _MARCATORI_BLOCCO_SICUREZZA):
        raise AccessoBloccato("E-Distribuzione blocca l'app con una regola Transaction Security")


# Rifiuti di loginUser che non riguardano email/password: un blocco lato
# portale (regola di sicurezza, account bloccato dall'amministratore)
# mostrato come "credenziali non valide" manderebbe l'utente a ricontrollare
# dati corretti e a ritentare, peggiorando il blocco.
_MARCATORI_LOGIN_BLOCCATO = (
    "transaction security",
    "blocked",
    "bloccat",
    "amministratore",
    "administrator",
)

# 'KO: Errore Tecnico' e' stato osservato su un account con credenziali
# corrette: non va confuso con un rifiuto delle credenziali.
_MARCATORI_ERRORE_SERVIZIO = (
    "errore tecnico",
    "technical error",
)


def _verifica_login_non_bloccato(messaggio: str) -> None:
    """Classifica i rifiuti di loginUser che non riguardano le credenziali."""
    if _contiene(messaggio, _MARCATORI_LOGIN_BLOCCATO):
        raise AccessoBloccato(f"E-Distribuzione ha bloccato il login: {messaggio[:200]}")
    if _contiene(messaggio, _MARCATORI_ERRORE_SERVIZIO):
        raise ErroreServizio(
            f"E-Distribuzione ha risposto con un errore tecnico: {messaggio[:200]}"
        )


async def _leggi_testo(resp: aiohttp.ClientResponse) -> str:
    """Corpo della risposta, dopo aver escluso la pagina antibot."""
    testo = await resp.text()
    _verifica_non_bloccato(testo)
    return testo


class ParsingError(AuthError):
    """La pagina scrapata non conteneva quanto ci si aspettava.

    Causa più probabile: Enel ha cambiato qualcosa nel loro sito Salesforce e
    le regex sotto vanno aggiornate. Cattura una HAR fresca e confronta.
    """


class AuraSessionScaduta(AuthError):
    """La sessione web Aura (cookie sid / token CSRF) non è più valida.

    Segnale interno: il chiamante riapre la sessione web con frontdoor e
    riprova. Non dovrebbe raggiungere l'utente.
    """


async def _get_following_redirects(
    session: aiohttp.ClientSession,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    riscrivi=None,
) -> aiohttp.ClientResponse:
    """GET seguendo i redirect a mano invece di allow_redirects=True.

    Necessario perché la catena di redirect di /services/oauth2/authorize
    passa per un parametro 'startURL' che contiene un URL annidato
    percent-encoded. Lasciando che aiohttp gestisca i redirect da solo, il
    comportamento dipende da come la libreria ri-codifica un URL già
    codificato ad ogni hop e può entrare in un loop infinito
    (TooManyRedirects, riprodotto e confermato con un HAR reale). Seguendo i
    redirect esplicitamente con encoded=True sull'URL del prossimo hop, il
    valore del Location non viene mai ri-processato: la stessa catena che con
    allow_redirects=True va in loop qui si risolve in pochi hop.

    Ritorna la risposta finale (status < 300, nessun altro Location); il
    chiamante è responsabile di chiudere/consumare 'resp' come al solito.
    """
    request_headers = dict(headers or {})
    resp = await session.get(
        url, params=params, headers=request_headers, allow_redirects=False
    )

    for _ in range(_MAX_REDIRECT_HOPS):
        location = resp.headers.get("Location")
        if location is None:
            return resp

        if request_headers.get("Sec-Fetch-Mode") == "navigate":
            # Come la webview dell'app: dopo il primo hop i redirect sono
            # navigazioni same-origin e portano il Referer della pagina
            # precedente. Senza questi segnali Imperva classifica più
            # facilmente il client come automatico.
            request_headers["Referer"] = str(resp.url)
            request_headers["Sec-Fetch-Site"] = "same-origin"

        resp.close()
        location_url = aiohttp.client.URL(location, encoded=True)
        next_url = location_url if location_url.is_absolute() else resp.url.join(location_url)
        # Il Location puo' puntare all'ALTRO dei due host della stessa org
        # (es. il dominio custom dietro Imperva mentre stiamo usando quello
        # diretto): va riscritto sull'host attivo o l'hop successivo trova
        # la pagina antibot invece della destinazione.
        if riscrivi is not None:
            next_url = aiohttp.client.URL(riscrivi(str(next_url)), encoded=True)
        resp = await session.get(next_url, headers=request_headers, allow_redirects=False)

    resp.close()
    raise AuthError(
        f"Troppi redirect (>{_MAX_REDIRECT_HOPS}) seguendo {url}: possibile "
        "cambiamento lato Salesforce nella struttura dei redirect di login."
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


@dataclass
class _LoginFlowState:
    """Tutto ciò che serve portare dalla pagina OTP alla sua sottomissione."""

    fwuid: str | None = None
    aura_token: str | None = None
    view_state: str | None = None
    view_state_version: str | None = None
    view_state_mac: str | None = None
    view_state_csrf: str | None = None
    form_action_url: str | None = None
    # I prefissi dei campi sotto 'thePage:j_id2:i:f:...' sono generati da
    # Salesforce e variano tra deploy: si conserva il nome scoperto sulla
    # pagina reale invece di dare per scontati quelli hardcoded (usati solo
    # come fallback nei rispettivi costruttori di form).
    otp_field_name: str | None = None
    resend_field_name: str | None = None
    # La checkbox visibile "Richiedi nuovo OTP", gemella del campo nascosto
    # sopra: serve solo per il reinvio esplicito, dove riproduciamo il submit
    # di un browser con la casella spuntata.
    resend_checkbox_field_name: str | None = None
    next_field_name: str | None = None


@dataclass
class OAuthTokens:
    access_token: str
    refresh_token: str
    instance_url: str
    id_token: str | None = None
    raw: dict = field(default_factory=dict)


class AuthClient:
    """Guida la sequenza login -> OTP -> code OAuth -> scambio token."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self._session = session
        # Host Salesforce attivo: ogni login e ogni refresh ripartono dal
        # primario; il diretto subentra solo se il primario risponde con la
        # pagina antibot (vedi async_begin_login/async_refresh_access_token).
        self._host = SF_HOST_PRINCIPALE
        self._code_verifier: str | None = None
        self._oauth_state: str | None = None
        self._flow = _LoginFlowState()
        # Stato della sessione web Aura (vedi _apri_sessione_web): la stringa
        # aura.context serializzata e il token CSRF delle POST Aura.
        self._aura_context: str | None = None
        self._aura_token: str | None = None
        # True/False dopo async_begin_login()/async_resend_otp() a seconda
        # che il portale abbia confermato l'invio del codice; None finché non
        # ci si è arrivati. Il config flow lo usa per avvisare l'utente
        # invece di lasciarlo aspettare un OTP che non arriverà mai.
        self.otp_invio_confermato: bool | None = None

    @property
    def _origine(self) -> str:
        return f"https://{self._host}"

    def _su_host(self, url: str) -> str:
        """Riscrive sull'host attivo gli URL assoluti che il server genera
        puntando all'altro dei due host della stessa org Salesforce.

        Salesforce conosce il proprio dominio pubblico e lo usa negli URL
        assoluti che produce (returnValue di loginUser con frontdoor.jsp,
        window.location della pagina-ponte, meta Location, action dei form):
        seguirli così come sono, mentre si lavora sul dominio diretto,
        riporterebbe dentro la verifica antibot. La riscrittura vale in
        ENTRAMBE le direzioni: se l'host attivo è il primario e il server
        genera un URL su *.my.site.com, anch'esso viene riportato sul
        primario. URL relativi o su host estranei passano invariati.
        """
        for host in SF_HOSTS:
            prefisso = f"https://{host}"
            if url.startswith(prefisso):
                return self._origine + url[len(prefisso) :]
        return url

    # -- Passo 1-4: login + OTP -------------------------------------------

    async def async_begin_login(self, email: str, password: str) -> None:
        """Sottomette email/password e arriva alla pagina OTP pronta per la
        convalida. Alza un'eccezione se le credenziali vengono rifiutate.

        Prova prima l'host primario; se Imperva risponde con la pagina
        antibot riparte da capo sull'host diretto, e AccessoBloccato arriva
        al chiamante solo se bloccati entrambi. Assume sempre che segua un
        passo OTP, coerente con ogni cattura vista finora.
        """
        await self._con_fallback_host(
            lambda: self._async_begin_login_su_host(email, password), "Login"
        )

    async def _con_fallback_host(self, tentativo, operazione: str):
        """Esegue un'operazione di rete partendo SEMPRE dall'host primario;
        se Imperva risponde con la pagina antibot ripete sull'host diretto.

        AccessoBloccato arriva al chiamante solo se sono bloccati entrambi.
        Siccome ogni operazione riparte dal primario, l'integrazione torna
        da sola al dominio ufficiale quando Enel toglie il blocco.
        """
        self._host = SF_HOST_PRINCIPALE
        try:
            return await tentativo()
        except AccessoBloccato:
            if self._host == SF_HOST_DIRETTO:
                raise
            _LOGGER.warning(
                "%s bloccato dall'antibot su %s: riprovo dall'host diretto %s",
                operazione,
                self._host,
                SF_HOST_DIRETTO,
            )
            self._host = SF_HOST_DIRETTO
            return await tentativo()

    async def _async_begin_login_su_host(self, email: str, password: str) -> None:
        """Un tentativo completo di login sull'host attivo: i token di flow
        e l'esito dell'invio OTP del tentativo precedente vanno azzerati,
        perché appartenevano a una sessione diversa."""
        self._flow = _LoginFlowState()
        self.otp_invio_confermato = None
        login_page_html, start_url_value, aura_page_uri, referer = (
            await self._carica_pagina_login(email)
        )
        frontdoor_url = await self._invia_credenziali(
            email, password, login_page_html, start_url_value, aura_page_uri, referer
        )
        otp_page_html = await self._segui_a_pagina_otp(frontdoor_url)
        self._analizza_pagina_otp(otp_page_html)
        await self._async_avvia_invio_otp()

    async def _carica_pagina_login(self, email: str) -> tuple[str, str, str, str]:
        """Passo 1: GET /oauth2/authorize con PKCE, seguendo i redirect a
        mano (vedi _get_following_redirects) fino alla pagina di login
        Salesforce. Genera anche code_verifier/oauth_state usati più avanti.

        Ritorna (login_page_html, start_url_value, aura_page_uri, referer).
        """
        self._code_verifier, code_challenge = _make_pkce_pair()
        self._oauth_state = _b64url(secrets.token_bytes(16))

        headers = _headers_navigazione()
        params = {
            "prompt": "login",
            "nonce": _b64url(secrets.token_bytes(16)),
            "display": "touch",
            "response_type": "code",
            "scope": OAUTH_SCOPE,
            "login_hint": email,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "redirect_uri": OAUTH_REDIRECT_URI,
            "client_id": OAUTH_CLIENT_ID,
            "state": self._oauth_state,
        }

        resp = await _get_following_redirects(
            self._session,
            self._su_host(OAUTH_AUTHORIZE_URL),
            params=params,
            headers=headers,
            riscrivi=self._su_host,
        )
        login_page_html = await _leggi_testo(resp)
        # Il campo loginUser 'startUrl' NON è il parametro startURL decodificato:
        # nel codice JS di c:PED_Login (verificato su auraCmpDef con REA)
        # doInit esegue window.location.href.split('startURL=')[1].split('%2F').join('/')
        # lasciando '%3F', '%26' e '%253D' del token 'source' percent-encoded
        # e mantenendo in coda i parametri che seguono 'startURL=' sull'host
        # primario (login_hint/display/sdtd/dch). Su *.my.site.com Salesforce
        # riordina la query mettendo dch/display/sdtd PRIMA di startURL:
        # _estrai_start_url_flow li riporta in coda così il controller Apex
        # riceve la stessa stringa dell'app ufficiale.
        start_url_value = self._estrai_start_url_flow(str(resp.url))
        aura_page_uri = resp.url.path_qs
        referer = str(resp.url)
        resp.close()
        return login_page_html, start_url_value, aura_page_uri, referer

    @staticmethod
    def _estrai_start_url_flow(url: str) -> str:
        """Estrae il valore 'startUrl' così come lo costruisce c:PED_Login.

        Nel JS di PED_Login.doInit (auraCmpDef):
            var startUrlsplit = window.location.href.split('startURL=')[1].split('%2F');
            component.set("v.startUrl", startUrlsplit.join('/'));
        Sull'host primario 'startURL=' è il primo parametro della query e
        quindi include in coda '&login_hint=...&display=touch&sdtd=1&dch=...'.
        Se invece 'startURL=' è preceduto da altri parametri (come su
        *.my.site.com dove la query è ordinata alfabeticamente), conserva la
        parte dopo 'startURL=' decodificando solo '%2F' -> '/'.
        """
        query = urlsplit(url).query
        marker = "startURL="
        if marker not in query:
            return "/PortaleClienti/setup/secur/RemoteAccessAuthorizationPage.apexp"
        return query.split(marker, 1)[1].replace("%2F", "/").replace("%2f", "/")

    async def _invia_credenziali(
        self,
        email: str,
        password: str,
        login_page_html: str,
        start_url_value: str,
        aura_page_uri: str,
        referer: str,
    ) -> str:
        """Passo 2: estrae fwuid/loaded dalla pagina di login, sottomette
        l'azione Aura loginUser, e ritorna l'URL di frontdoor.jsp da
        seguire."""
        headers = _headers_ajax()

        self._flow.fwuid = self._estrai_fwuid(login_page_html)
        loaded = self._estrai_loaded(login_page_html)
        # Nella cattura dell'app del 14/10/2026 loginUser manda il valore
        # del cookie CSRF indicato da auraConfig.eikoocnekot. Sul dominio
        # diretto la pagina non espone quel cookie ma pubblica lo stesso
        # token inline come auraConfig.ConnectCSRFToken: senza di esso
        # loginUser può fallire con 'KO: Errore Tecnico' dopo aver
        # riconosciuto credenziali valide.
        try:
            self._flow.aura_token = self._estrai_token_aura_login(login_page_html)
        except ParsingError as err:
            _LOGGER.warning(
                "Token CSRF Aura non trovato sulla pagina di login (%s): "
                "riprovo con aura.token='null'",
                err,
            )
            self._flow.aura_token = "null"

        # json.dumps invece di concatenazione di stringhe: evita JSON
        # malformato se email/password contenessero virgolette o backslash.
        message = json.dumps({
            "actions": [{
                # ID Aura distinto per ogni azione della pagina: nella
                # cattura dell'app loginUser usa "107;a".
                "id": "107;a",
                "descriptor": "apex://PED_LoginController/ACTION$loginUser",
                "callingDescriptor": "markup://c:PED_Login",
                "params": {
                    "username": email,
                    "password": password,
                    "startUrl": start_url_value,
                },
            }]
        })
        # 'loaded' NON può essere {} (vuoto): il server risponde con un
        # generico AuraClientInputException se non corrisponde a quanto si
        # aspetta - confermato confrontando con una richiesta reale riuscita,
        # dove conteneva un riferimento alla versione del componente
        # caricato (es. {"APPLICATION@markup://siteforce:loginApp2":"..."}).
        aura_context = json.dumps({
            "mode": "PROD",
            "fwuid": self._flow.fwuid,
            "app": "siteforce:loginApp2",
            "loaded": json.loads(loaded),
            "dn": [],
            "globals": {},
            "uad": True,
        })
        # Nella cattura tutte le chiamate Aura della stessa pagina riusano
        # lo stesso Page-Scope-Id: non va rigenerato tra init e loginUser.
        page_scope_id = str(uuid.uuid4())
        await self._async_configura_host_aura(
            headers, aura_context, aura_page_uri, referer, page_scope_id
        )
        await self._async_inizializza_componente_login(
            headers, aura_context, aura_page_uri, referer, page_scope_id
        )
        data = {
            "message": message,
            "aura.context": aura_context,
            "aura.pageURI": aura_page_uri,
            "aura.token": self._flow.aura_token,
        }

        # X-SFDC-Page-Scope-Id: mai visto in nessuna risposta del server,
        # solo nelle richieste - verosimilmente generato lato client (un ID
        # di correlazione riusato identico su tutte le chiamate Aura).
        # Origin/Referer/Content-Type: presenti nella richiesta reale
        # riuscita, non individualmente confermati come necessari ma a
        # rischio zero da aggiungere.
        login_headers = {
            **headers,
            "X-SFDC-Page-Scope-Id": page_scope_id,
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Origin": self._origine,
            "Referer": referer,
        }

        async with self._session.post(
            f"{self._su_host(AURA_ENDPOINT)}?r=2&other.PED_Login.loginUser=1",
            data=data,
            headers=login_headers,
        ) as resp:
            raw_text = await _leggi_testo(resp)
            try:
                payload = json.loads(raw_text)
            except json.JSONDecodeError as err:
                _LOGGER.error(
                    "Risposta non-JSON da loginUser (status %s). Primi 500 "
                    "caratteri del corpo: %r",
                    resp.status,
                    raw_text[:500],
                )
                raise ParsingError(
                    f"Risposta non-JSON da loginUser (status {resp.status}): "
                    f"{raw_text[:200]!r}"
                ) from err

        try:
            return_value = payload["actions"][0]["returnValue"]
        except (KeyError, IndexError) as err:
            raise ParsingError("Forma inattesa della risposta di loginUser") from err

        if not isinstance(return_value, str) or not return_value.startswith("OK:"):
            # Il limite di sessioni contemporanee arriva qui come messaggio
            # di errore della stessa action del login: trattarlo come
            # "credenziali non valide" manderebbe l'utente a ricontrollare
            # email e password mentre il problema è altrove.
            self._verifica_non_troppe_sessioni(str(return_value))
            _verifica_login_non_bloccato(str(return_value))
            # Il testo del portale finisce nel log: senza, ogni rifiuto
            # appare solo come "Email o password non valide".
            _LOGGER.warning("loginUser ha rifiutato l'accesso: %r", str(return_value)[:300])
            raise InvalidCredentials(str(return_value))

        # Seguirlo stabilisce il cookie di sessione 'sid' e atterra su una
        # pagina-ponte che fa un redirect via JAVASCRIPT (non HTTP) verso il
        # vero form OTP - vedi _segui_a_pagina_otp. L'URL arriva col dominio
        # pubblico dietro Imperva: si riscrive sull'host attivo.
        return self._su_host(return_value[len("OK:") :])

    async def _async_configura_host_aura(
        self,
        headers: dict[str, str],
        aura_context: str,
        aura_page_uri: str,
        referer: str,
        page_scope_id: str,
    ) -> None:
        """Bootstrap Aura della pagina di login dell'app iOS.

        La cattura mostra due serviceComponent prima di PED_Login.init. I
        valori restituiti non sono riusati nei passi seguenti: per questo un
        esito non-SUCCESS viene solo loggato, mentre gli errori di rete o le
        pagine antibot restano fatali come nelle altre chiamate.
        """
        message = json.dumps({
            "actions": [
                {
                    "id": "20;a",
                    "descriptor": (
                        "serviceComponent://ui.chatter.components.messages."
                        "MessagesController/ACTION$getMessagingPermAndPref"
                    ),
                    "callingDescriptor": "UNKNOWN",
                    "params": {},
                },
                {
                    "id": "37;a",
                    "descriptor": (
                        "serviceComponent://ui.force.components.controllers."
                        "hostConfig.HostConfigController/ACTION$getConfigData"
                    ),
                    "callingDescriptor": "UNKNOWN",
                    "params": {},
                },
            ]
        })
        data = {
            "message": message,
            "aura.context": aura_context,
            "aura.pageURI": aura_page_uri,
            "aura.token": self._flow.aura_token or "null",
        }
        config_headers = {
            **headers,
            "X-SFDC-Page-Scope-Id": page_scope_id,
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Origin": self._origine,
            "Referer": referer,
        }
        async with self._session.post(
            f"{self._su_host(AURA_ENDPOINT)}?r=0&"
            "ui-chatter-components-messages.Messages.getMessagingPermAndPref=1&"
            "ui-force-components-controllers-hostConfig.HostConfig.getConfigData=1",
            data=data,
            headers=config_headers,
        ) as resp:
            raw_text = await _leggi_testo(resp)
        try:
            azioni = json.loads(raw_text)["actions"]
            stati = [azione.get("state") for azione in azioni]
        except (json.JSONDecodeError, KeyError, TypeError) as err:
            raise ParsingError("Risposta non-JSON al bootstrap Aura del login") from err
        if stati != ["SUCCESS"] * len(stati):
            _LOGGER.warning(
                "Bootstrap Aura del login non completato (%s): continuo con PED_Login.init",
                stati,
            )

    async def _async_inizializza_componente_login(
        self,
        headers: dict[str, str],
        aura_context: str,
        aura_page_uri: str,
        referer: str,
        page_scope_id: str,
    ) -> None:
        """PED_Login.init, chiamato dall'app prima di loginUser.

        Nella cattura del 14/10/2026 la sequenza è getConfigData -> init ->
        loginUser. Senza init Salesforce può rispondere al login con un
        generico 'KO: Errore Tecnico' anche se il payload è ben formato.
        """
        message = json.dumps({
            "actions": [{
                "id": "53;a",
                "descriptor": "apex://PED_LoginController/ACTION$init",
                "callingDescriptor": "markup://c:PED_Login",
                "params": {},
            }]
        })
        data = {
            "message": message,
            "aura.context": aura_context,
            "aura.pageURI": aura_page_uri,
            "aura.token": self._flow.aura_token or "null",
        }
        init_headers = {
            **headers,
            "X-SFDC-Page-Scope-Id": page_scope_id,
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Origin": self._origine,
            "Referer": referer,
        }
        async with self._session.post(
            f"{self._su_host(AURA_ENDPOINT)}?r=1&other.PED_Login.init=1",
            data=data,
            headers=init_headers,
        ) as resp:
            raw_text = await _leggi_testo(resp)
        try:
            payload = json.loads(raw_text)
            azione = payload["actions"][0]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as err:
            raise ParsingError("Risposta non-JSON a PED_Login.init") from err
        if azione.get("state") != "SUCCESS":
            raise AuthError(
                f"Inizializzazione del login rifiutata da Salesforce: {raw_text[:300]}"
            )

    async def _segui_a_pagina_otp(self, frontdoor_url: str) -> str:
        """Passo 3: frontdoor.jsp stabilisce il cookie di sessione 'sid' e
        atterra su una pagina-ponte che fa un redirect via JAVASCRIPT
        (window.location.replace(...), non un redirect HTTP) verso il vero
        form OTP - un browser lo segue automaticamente, qui va estratto e
        seguito a mano.
        """
        headers = _headers_navigazione("same-origin")

        resp = await _get_following_redirects(
            self._session, frontdoor_url, headers=headers, riscrivi=self._su_host
        )
        bridge_html = await _leggi_testo(resp)
        resp.close()

        otp_form_url = self._su_host(self._estrai_url_redirect_js(bridge_html))
        resp = await _get_following_redirects(
            self._session, otp_form_url, headers=headers, riscrivi=self._su_host
        )
        otp_page_html = await _leggi_testo(resp)
        resp.close()
        # Password scaduta: al posto del form OTP arriva direttamente il
        # form di rinnovo - va intercettato prima di cercare i campi OTP.
        _verifica_non_password_scaduta(otp_page_html)
        return otp_page_html

    async def _async_avvia_invio_otp(self) -> None:
        """Passo 4: il form OTP non parte da solo al caricamento della
        pagina - serve un primo submit del bottone, SENZA codice, per farlo
        davvero inviare (confermato su HAR reale: la risposta contiene
        testualmente "Abbiamo inviato un codice a 5 cifre al tuo indirizzo
        email", non solo SMS nonostante il nome del campo)."""
        await self._async_post_form_otp(self._form_invio_iniziale())

    async def async_resend_otp(self) -> bool:
        """Fa rimandare un OTP nuovo DENTRO la sessione di login già avviata.

        Serve perché un OTP generato altrove (app ufficiale o sito) appartiene
        a un'altra "interview" del login flow di Salesforce e non può essere
        convalidato qui: se il codice non arriva, l'unico modo di ottenerne
        uno valido è farlo rispedire da questa stessa sessione.

        Ritorna True se il portale ha confermato l'invio.
        """
        if self._flow.view_state is None:
            raise AuthError("async_begin_login() deve riuscire prima di async_resend_otp()")
        await self._async_post_form_otp(self._form_richiedi_nuovo())
        return bool(self.otp_invio_confermato)

    def _campi_comuni_form_otp(self) -> dict[str, str]:
        """Campi RichFaces comuni a tutti i submit del login flow (invio
        iniziale, reinvio, convalida): cambiano solo il campo OTP e il flag
        di reinvio, gestiti dai tre costruttori sotto."""
        next_field = self._flow.next_field_name or _CAMPO_NEXT_AJAX_DEFAULT
        return {
            "AJAXREQUEST": "_viewRoot",
            "thePage:j_id2:i:f": "thePage:j_id2:i:f",
            "thePage:j_id2:i:f:pb:d:navigationType": "",
            "com.salesforce.visualforce.ViewState": self._flow.view_state,
            "com.salesforce.visualforce.ViewStateVersion": self._flow.view_state_version,
            "com.salesforce.visualforce.ViewStateMAC": self._flow.view_state_mac,
            "com.salesforce.visualforce.ViewStateCSRF": self._flow.view_state_csrf,
            next_field: next_field,
        }

    def _form_invio_iniziale(self) -> dict[str, str]:
        """Primo submit, vuoto: niente campo OTP né flag di reinvio - un
        submit "neutro" del form appena caricato, che però è ciò che fa
        davvero partire l'invio del codice (vedi _async_avvia_invio_otp)."""
        return self._campi_comuni_form_otp()

    def _form_richiedi_nuovo(self) -> dict[str, str]:
        """Submit con la richiesta di un nuovo codice: imposta il flag di
        reinvio (campo nascosto) più la checkbox visibile che lo specchia,
        se conosciuta - vedi il commento sui due campi omonimi in
        _analizza_pagina_otp."""
        dati = self._campi_comuni_form_otp()
        dati[self._flow.resend_field_name or _CAMPO_RICHIEDI_NUOVO_OTP_DEFAULT] = "true"
        if self._flow.resend_checkbox_field_name:
            dati[self._flow.resend_checkbox_field_name] = "true"
        return dati

    def _form_convalida(self, otp_code: str) -> dict[str, str]:
        """Submit con il codice da convalidare."""
        dati = self._campi_comuni_form_otp()
        dati[self._flow.otp_field_name or _CAMPO_OTP_INPUT_DEFAULT] = otp_code
        dati[self._flow.resend_field_name or _CAMPO_RICHIEDI_NUOVO_OTP_DEFAULT] = "false"
        return dati

    async def _async_post_form_otp(self, data: dict[str, str]) -> None:
        """Submit del form OTP che NON porta un codice da convalidare (invio
        iniziale o reinvio): controlla che il portale abbia davvero spedito
        l'OTP e aggiorna ViewState/CSRF dalla risposta.

        I token nella risposta di QUESTA chiamata sono quelli da usare per
        l'invio effettivo del codice (async_submit_otp), non quelli della
        pagina di atterraggio: ruotano ad ogni submit del form.
        """
        url = self._su_host(self._flow.form_action_url or LOGINFLOW_URL)
        headers = {
            **_headers_ajax(),
            "Faces-Request": "partial/ajax",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": self._origine,
            "Referer": url,
        }
        async with self._session.post(url, data=data, headers=headers) as resp:
            body = await _leggi_testo(resp)

        self._verifica_non_troppe_sessioni(body, "otp_send_debug.html")
        _verifica_non_password_scaduta(body)

        self.otp_invio_confermato = _contiene(body, _MARCATORI_OTP_INVIATO)
        if not self.otp_invio_confermato:
            # Non fatale di proposito: la pagina potrebbe confermare l'invio
            # con parole che non conosciamo ancora, e abortire qui
            # romperebbe login altrimenti validi. Ma va segnalato, perché
            # l'altra possibilità è che il codice non sia MAI stato spedito.
            _LOGGER.error(
                "E-Distribuzione non ha confermato l'invio del codice OTP "
                "(nessuno dei messaggi attesi %r nella risposta, lunga %d "
                "caratteri). Se il codice non arriva né via email né via "
                "SMS, allega otp_send_debug.html alla segnalazione.",
                _MARCATORI_OTP_INVIATO,
                len(body),
            )
            _salva_pagina_debug(body, "otp_send_debug.html")

        self._analizza_pagina_otp(body)

    # -- Passi 5-8: convalida OTP + scambio token -------------------------

    async def async_submit_otp(self, otp_code: str) -> OAuthTokens:
        """Sottomette l'OTP e completa lo scambio del code OAuth2."""
        if self._flow.view_state is None:
            raise AuthError("async_begin_login() deve riuscire prima di async_submit_otp()")

        next_url = await self._sottometti_codice_otp(otp_code)
        consent_html = await self._scarica_pagina_dopo_otp(next_url)
        auth_code = await self._estrai_codice_autorizzazione(consent_html)
        return await self._async_exchange_code(auth_code)

    async def _sottometti_codice_otp(self, otp_code: str) -> str:
        """Passo 5: POST del form con il codice; ritorna l'URL scoperto nel
        meta tag Location della risposta."""
        data = self._form_convalida(otp_code)

        url = self._su_host(self._flow.form_action_url or LOGINFLOW_URL)
        headers = {
            **_headers_ajax(),
            "Faces-Request": "partial/ajax",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": self._origine,
            "Referer": url,
        }
        async with self._session.post(url, data=data, headers=headers) as resp:
            body = await _leggi_testo(resp)

        self._verifica_non_troppe_sessioni(body, "otp_submit_response_debug.html")
        _verifica_non_password_scaduta(body)

        if "Codice OTP" in body and "errato" in body.lower():
            raise InvalidOtp(body[:500])

        loc_match = re.search(r'name="Location"\s+content="([^"]+)"', body)
        if not loc_match:
            _log_parsing_failure_context(body, "meta Location dopo l'invio dell'OTP")
            _salva_pagina_debug(body, "otp_submit_response_debug.html")
            raise ParsingError(
                "Redirect (meta Location) non trovato nella risposta dopo "
                f"l'invio dell'OTP (risposta lunga {len(body)} caratteri - "
                "vedi log per un'anteprima)"
            )
        next_url = unquote(loc_match.group(1))
        if next_url.startswith("/"):
            next_url = self._origine + next_url
        return self._su_host(next_url)

    async def _scarica_pagina_dopo_otp(self, next_url: str) -> str:
        """Passo 6: GET della pagina a cui punta il redirect - di norma
        innesca poi un redirect JS verso eneldist://redirect?code=..., che
        aiohttp non può seguire (schema custom, non HTTP): il codice si
        scrapa dal testo qui sotto, non navigando."""
        headers = _headers_navigazione("same-origin")
        headers["Referer"] = self._su_host(
            self._flow.form_action_url or LOGINFLOW_URL
        )
        async with self._session.get(next_url, headers=headers) as resp:
            testo = await _leggi_testo(resp)
        _verifica_non_password_scaduta(testo)
        return testo

    async def _estrai_codice_autorizzazione(self, consent_html: str) -> str:
        """Passo 7: trova code/state nella pagina. Se assenti, è la prima
        autorizzazione di questo account: Salesforce mostra una schermata di
        consenso esplicita ("Consentire l'accesso?") invece di rimandare
        subito il codice - va approvata al posto dell'utente, poi si ricerca
        di nuovo. Dalla seconda volta in poi il consenso resta memorizzato
        lato Salesforce e questo ramo non viene più eseguito."""
        code_match = re.search(r"[?&]code=([^&'\"]+)", consent_html)
        state_match = re.search(r"[?&]state=([^&'\"]+)", consent_html)

        if not code_match:
            risposta_consenso = await self._async_approva_consenso(consent_html)
            if risposta_consenso is not None:
                consent_html = risposta_consenso
                code_match = re.search(r"[?&]code=([^&'\"]+)", consent_html)
                state_match = re.search(r"[?&]state=([^&'\"]+)", consent_html)

        if not code_match:
            _log_parsing_failure_context(
                consent_html, "authorization code sulla pagina di consenso"
            )
            _salva_pagina_debug(consent_html, "consent_page_debug.html")
            raise ParsingError(
                "Authorization code non trovato nella risposta della pagina "
                f"di consenso (pagina lunga {len(consent_html)} caratteri - "
                "vedi log per un'anteprima)"
            )

        self._valida_state(state_match)
        return unquote(code_match.group(1))

    def _valida_state(self, state_match: re.Match[str] | None) -> None:
        """Il parametro 'state' è la protezione CSRF standard di OAuth:
        generato e mandato da noi in _carica_pagina_login, dovrebbe tornare
        identico. Solo un warning, non un errore bloccante: non verificato
        dal vivo se il confronto regge sempre (es. differenze di codifica) -
        un falso positivo qui romperebbe un login altrimenti valido."""
        if state_match and unquote(state_match.group(1)) != self._oauth_state:
            _LOGGER.warning(
                "State OAuth nella risposta non corrisponde a quello inviato "
                "(atteso %r, ricevuto %r) - procedo comunque, ma segnalalo se "
                "il login inizia a fallire qui",
                self._oauth_state,
                state_match.group(1),
            )

    async def _async_approva_consenso(self, html: str) -> str | None:
        """Preme "Consenti" sulla schermata di consenso OAuth di Salesforce.

        Ritorna il testo con cui cercare il codice di autorizzazione: il
        Location della risposta se c'è un redirect (tipicamente verso
        eneldist://redirect?code=..., che aiohttp non può seguire perché non
        è uno schema HTTP), altrimenti il corpo della risposta. Ritorna None
        se questa pagina non è una schermata di consenso riconoscibile, così
        il chiamante prosegue con il suo errore di parsing abituale.
        """
        form = self._estrai_form_consenso(html)
        if form is None:
            return None

        action_url, dati = form
        _LOGGER.info(
            "Schermata di consenso OAuth rilevata (prima autorizzazione di "
            "questo account): confermo con %r",
            dati.get("save"),
        )
        headers = {
            **_headers_navigazione("same-origin"),
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self._origine,
            "Referer": f"{self._origine}/PortaleClienti/",
        }
        # allow_redirects=False: il redirect punta allo schema custom
        # dell'app (eneldist://), che aiohttp non sa seguire - il codice sta
        # nel Location, che qui possiamo leggere direttamente.
        async with self._session.post(
            action_url, data=dati, headers=headers, allow_redirects=False
        ) as resp:
            location = resp.headers.get("Location")
            body = await _leggi_testo(resp)
        return location or body

    def _estrai_form_consenso(self, html: str) -> tuple[str, dict[str, str]] | None:
        """Trova il form della schermata di consenso e costruisce il
        payload da rimandare: tutti i campi hidden così come sono, più il
        pulsante di approvazione.

        Ritorna (url_action, dati) oppure None se non c'è un form con un
        pulsante di approvazione riconoscibile.
        """
        for form_match in re.finditer(r"<form[^>]*>.*?</form>", html, re.IGNORECASE | re.DOTALL):
            blocco = form_match.group(0)
            approva: tuple[str, str] | None = None
            for input_match in re.finditer(r"<input[^>]*>", blocco, re.IGNORECASE):
                tag = input_match.group(0)
                if not re.search(r'type="submit"', tag, re.IGNORECASE):
                    continue
                nome = re.search(r'name="([^"]*)"', tag)
                valore = re.search(r'value="([^"]*)"', tag)
                if not nome or not valore:
                    continue
                etichetta = html_lib.unescape(valore.group(1))
                if etichetta.strip().lower() in _ETICHETTE_CONSENSO:
                    approva = (nome.group(1), etichetta)
                    break
            if approva is None:
                continue

            dati = {}
            for input_match in re.finditer(r"<input[^>]*>", blocco, re.IGNORECASE):
                tag = input_match.group(0)
                if not re.search(r'type="hidden"', tag, re.IGNORECASE):
                    continue
                nome = re.search(r'name="([^"]*)"', tag)
                if not nome:
                    continue
                valore = re.search(r'value="([^"]*)"', tag)
                # I valori nell'HTML sono escapati (&amp;, &#39;): vanno
                # riportati in chiaro, altrimenti il server riceve campi
                # diversi da quelli che ha generato (save_new_url e source
                # sono URL pieni di parametri).
                dati[nome.group(1)] = html_lib.unescape(valore.group(1)) if valore else ""
            dati[approva[0]] = approva[1]

            action = re.search(r'<form[^>]*action="([^"]*)"', blocco, re.IGNORECASE)
            action_url = html_lib.unescape(action.group(1)) if action else ""
            if not action_url:
                return None
            if action_url.startswith("/"):
                action_url = self._origine + action_url
            return self._su_host(action_url), dati

        return None

    @staticmethod
    def _verifica_non_troppe_sessioni(testo: str, nome_file_debug: str | None = None) -> None:
        """Alza TroppeSessioni se il testo contiene uno dei marcatori noti.

        Centralizza un controllo che nel protocollo originale compare in tre
        punti diversi del flusso (risposta di loginUser, submit senza
        codice, submit con codice) con lo stesso identico significato."""
        if not _contiene(testo, _MARCATORI_TROPPE_SESSIONI):
            return
        if nome_file_debug:
            _salva_pagina_debug(testo, nome_file_debug)
        raise TroppeSessioni(testo[:500])

    # -- Login via browser (l'unico che Imperva lascia passare) -------------

    def _url_authorize_browser(self, email: str | None = None) -> str:
        """URL /oauth2/authorize da far aprire all'utente in un browser reale
        DOPO aver effettuato l'accesso su private.e-distribuzione.it.

        Usa il flusso OAuth user-agent (response_type=token) SENZA
        prompt=login e SENZA login_hint:
        - Con prompt=login (o in un browser non ancora autenticato sul
          portale), /oauth2/authorize redirige alla pagina di login di
          edistribuzione.my.site.com, dove PED_LoginController.loginUser
          rifiuta le credenziali valide con 'KO: Errore Tecnico' anche in un
          browser reale.
        - Invece, accedendo prima su https://private.e-distribuzione.it/PortaleClienti/s/login/
          e aprendo poi questo URL nella stessa finestra del browser,
          Salesforce riusa la sessione già attiva su private.e-distribuzione.it
          ed emette subito eneldist://redirect#access_token=...&refresh_token=...
          senza passare da edistribuzione.my.site.com e senza richiedere una
          seconda chiamata POST a /oauth2/token da Home Assistant.
        """
        del email
        self._code_verifier, _ = _make_pkce_pair()
        self._oauth_state = _b64url(secrets.token_bytes(16))
        params = {
            "nonce": _b64url(secrets.token_bytes(16)),
            "display": "touch",
            "response_type": "token",
            "scope": OAUTH_SCOPE,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "client_id": OAUTH_CLIENT_ID,
            "state": self._oauth_state,
        }
        return f"{OAUTH_AUTHORIZE_URL}?{urlencode(params)}"

    async def async_scambia_url_browser(self, redirect_url: str) -> OAuthTokens:
        """Completa il login fatto nel browser dall'utente.

        Accetta sia l'indirizzo 'eneldist://redirect...' da solo sia l'intera
        riga della Console sviluppatori del browser che lo contiene (es.
        "Failed to launch 'eneldist://redirect#access_token=...' because the
        scheme does not have a registered handler.").

        Supporta entrambi i formati di redirect OAuth:
        - Fragment (#access_token=...&refresh_token=...&state=...): generato
          da _url_authorize_browser (response_type=token); restituisce
          direttamente i token senza contattare /oauth2/token.
        - Query (?code=...&state=...): retrocompatibilità col flusso
          Authorization Code + PKCE; scambia 'code' sul token endpoint.
        """
        testo = (redirect_url or "").strip()
        match = _RE_REDIRECT_APP.search(testo)
        url_trovato = match.group(0) if match is not None else testo
        parti = urlsplit(url_trovato)
        if parti.scheme != "eneldist" or (not parti.fragment and not parti.query):
            raise LoginBrowserError("url")

        parametri = _parametri_redirect(url_trovato)
        if "error" in parametri:
            descrizione = parametri.get("error_description", "").replace("+", " ")
            if _contiene(f"{parametri['error']} {descrizione}", _MARCATORI_BLOCCO_SICUREZZA):
                raise AccessoBloccato(
                    f"E-Distribuzione blocca l'app OAuth: {parametri['error']} ({descrizione})"
                )
            raise CodiceNonValido(
                f"Autorizzazione nel browser rifiutata: {parametri['error']} ({descrizione})"
            )

        state_ricevuto = parametri.get("state", "")
        if self._oauth_state is None or not secrets.compare_digest(
            state_ricevuto, self._oauth_state
        ):
            raise LoginBrowserError("state")

        if "access_token" in parametri or "refresh_token" in parametri:
            if not parametri.get("access_token") or not parametri.get("refresh_token"):
                raise LoginBrowserError("url")
            return self._tokens_from_payload(parametri)

        codice = parametri.get("code")
        if not codice:
            raise LoginBrowserError("url")
        return await self._con_fallback_host(
            lambda: self._async_exchange_code_browser(codice),
            "Scambio del codice OAuth",
        )

    async def _async_exchange_code_browser(self, code: str) -> OAuthTokens:
        """_async_exchange_code con l'errore OAuth mappato su CodiceNonValido:
        un 'invalid_grant' qui significa codice scaduto o già usato, non un
        problema di parsing."""
        data = {
            "code": code,
            "code_verifier": self._code_verifier,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "client_id": OAUTH_CLIENT_ID,
            "grant_type": "authorization_code",
        }
        async with self._session.post(
            self._su_host(OAUTH_TOKEN_URL), data=data, headers=_headers_app()
        ) as resp:
            testo = await _leggi_testo(resp)
            _verifica_non_bloccato(testo)
            payload = self._json_token(testo, resp.status)
        if "error" in payload:
            raise CodiceNonValido(
                f"Scambio del codice rifiutato: {payload.get('error')} - "
                f"{payload.get('error_description', '')[:200]}"
            )
        return self._tokens_from_payload(payload)

    # -- Scambio/refresh del token ------------------------------------------

    async def _async_exchange_code(self, code: str) -> OAuthTokens:
        """Passo 8: scambia l'authorization code per una coppia di token."""
        data = {
            "code": code,
            "code_verifier": self._code_verifier,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "client_id": OAUTH_CLIENT_ID,
            "grant_type": "authorization_code",
        }
        async with self._session.post(
            self._su_host(OAUTH_TOKEN_URL), data=data, headers=_headers_app()
        ) as resp:
            payload = self._json_token(await _leggi_testo(resp), resp.status)
        return self._tokens_from_payload(payload)

    async def async_refresh_access_token(self, refresh_token: str) -> OAuthTokens:
        """Ottiene un access_token fresco. Nessun Aura/OTP coinvolto - è il
        percorso che l'integrazione usa a ogni avvio/rinnovo normale.

        Come il login: si parte sempre dall'host primario e si ripiega sul
        diretto solo se Imperva risponde con la pagina antibot, così quando
        il blocco viene tolto si torna da soli al dominio ufficiale.
        AccessoBloccato arriva al chiamante solo se bloccati entrambi.
        """
        return await self._con_fallback_host(
            lambda: self._async_refresh_su_host(refresh_token), "Refresh del token"
        )

    async def _async_refresh_su_host(self, refresh_token: str) -> OAuthTokens:
        """Un tentativo di refresh sull'host attivo."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": OAUTH_CLIENT_ID,
        }
        async with self._session.post(
            self._su_host(OAUTH_TOKEN_URL), data=data, headers=_headers_app()
        ) as resp:
            text = await _leggi_testo(resp)
            if resp.status != 200:
                raise AuthError(f"Scambio del refresh_token fallito ({resp.status}): {text[:300]}")
            payload = self._json_token(text, resp.status)
        # Salesforce non restituisce sempre un nuovo refresh_token al
        # refresh - si mantiene il vecchio se non ne arriva uno nuovo.
        payload.setdefault("refresh_token", refresh_token)
        return self._tokens_from_payload(payload)

    @staticmethod
    def _json_token(testo: str, status: int) -> dict:
        """JSON del token endpoint; una pagina HTML al suo posto è un
        ParsingError (quindi un AuthError), non un ValueError generico."""
        try:
            return json.loads(testo)
        except json.JSONDecodeError as err:
            raise ParsingError(
                f"Risposta non-JSON dal token endpoint (status {status}): {testo[:200]!r}"
            ) from err

    @staticmethod
    def _tokens_from_payload(payload: dict) -> OAuthTokens:
        try:
            return OAuthTokens(
                access_token=payload["access_token"],
                refresh_token=payload["refresh_token"],
                instance_url=payload.get("instance_url", ""),
                id_token=payload.get("id_token"),
                raw=payload,
            )
        except KeyError as err:
            raise ParsingError(f"Campo atteso mancante nella risposta del token endpoint: {err}") from err

    # -- Sessione web Aura (tabelle del portale: Misure GSE-TERNA) ----------
    # Le misure ufficiali trasmesse a GSE/Terna non passano dalle API
    # xs-misura ma dalle chiamate Aura della pagina /s/gse-terna, dentro la
    # sessione web aperta da frontdoor.jsp con l'access_token come sid.
    # Pipeline verificata su cattura mitmproxy:
    #   frontdoor.jsp?sid=<access_token>   -> cookie sid
    #   GET /s/gse-terna                   -> auraConfig (fwuid, cookie CSRF)
    #   POST aura callSuppliesByPodId      -> seleziona il POD in sessione
    #   POST aura QueryRegulatoryComplianceStatusService -> righe del mese

    async def async_get_misure_gse_terna(
        self, access_token: str, pod: str, yearmonth: str
    ) -> list[dict]:
        """Righe della tabella 'Misure GSE-TERNA' del portale per POD e mese.

        'yearmonth' nel formato 'YYYY-MM'. Ogni riga è il record grezzo
        restituito dall'azione Aura (energia prodotta/prelevata/immessa per
        fascia F1-F3 + totale, tipo incentivo, nome file, data di
        trasmissione, stato); la normalizzazione è a carico del chiamante.

        Va chiamato sul POD DI SCAMBIO: per un POD di produzione ITP... la
        query torna vuota - le sue misure sono aggregate sullo scambio
        collegato (campo POD_Scambio di callSuppliesByPodId).
        """
        return await self._con_fallback_host(
            lambda: self._async_misure_gse_terna(access_token, pod, yearmonth),
            "Lettura delle misure GSE-TERNA",
        )

    async def _async_misure_gse_terna(
        self, access_token: str, pod: str, yearmonth: str
    ) -> list[dict]:
        """Un tentativo sull'host attivo; la sessione web viene riaperta una
        seconda volta se il token CSRF risulta scaduto."""
        await self._apri_sessione_web(access_token)
        for tentativo in (1, 2):
            try:
                # Il POD non è un parametro della query: va selezionato
                # nello stato della sessione Salesforce.
                await self._aura_action(
                    "apex://PED_InfoAndData/ACTION$callSuppliesByPodId",
                    {"pod": pod, "fromDelegate": False},
                    "markup://c:PED_POD_Details",
                )
                return await self._aura_action(
                    "apex://PED_ServizidiMisuraController/"
                    "ACTION$QueryRegulatoryComplianceStatusService",
                    {"YearMonth": yearmonth, "Incentive": "", "isDelegate": False},
                    "markup://c:PED_Terna_GSE",
                )
            except AuraSessionScaduta:
                if tentativo == 2:
                    raise
                await self._apri_sessione_web(access_token)
        raise AssertionError("non raggiungibile")

    async def _apri_sessione_web(self, access_token: str) -> None:
        """Converte l'access_token in sessione web (cookie sid) via
        frontdoor.jsp e legge dalla pagina gse-terna la configurazione Aura
        (fwuid, loaded, nome del cookie CSRF). Può essere rilanciata per
        rinnovarla."""
        async with self._session.get(
            self._su_host(SF_FRONTDOOR_URL),
            params={"sid": access_token, "retURL": "/PortaleClienti/s/"},
            headers={"User-Agent": _BROWSER_USER_AGENT},
        ) as resp:
            await _leggi_testo(resp)
            resp.raise_for_status()
        async with self._session.get(
            self._su_host(GSE_TERNA_PAGE_URL),
            headers={"User-Agent": _BROWSER_USER_AGENT},
        ) as resp:
            html = await _leggi_testo(resp)
            resp.raise_for_status()
        self._aura_context, nome_cookie = self._estrai_aura_config(html)
        self._aura_token = self._aura_cookie_token(nome_cookie)

    @staticmethod
    def _estrai_aura_config_dict(html: str, pagina: str) -> dict:
        """Oggetto auraConfig incorporato in una pagina Salesforce."""
        match = re.search(r"var\s+auraConfig\s*=\s*(\{)", html)
        if not match:
            raise ParsingError(f"auraConfig non trovato nella pagina {pagina}")
        try:
            # raw_decode si ferma al primo oggetto: sulla stessa riga può
            # seguire altro JavaScript.
            cfg, _ = json.JSONDecoder().raw_decode(html, match.end(1) - 1)
        except (json.JSONDecodeError, TypeError) as err:
            raise ParsingError(f"auraConfig irriconoscibile: {err}") from err
        if not isinstance(cfg, dict):
            raise ParsingError("auraConfig irriconoscibile: non è un oggetto")
        return cfg

    @classmethod
    def _estrai_nome_cookie_aura(cls, html: str, pagina: str) -> str:
        """Nome del cookie il cui valore va inviato come aura.token."""
        cfg = cls._estrai_aura_config_dict(html, pagina)
        nome_cookie = cfg.get("eikoocnekot") or cfg.get("token")
        if not nome_cookie:
            raise ParsingError(
                f"Nome del cookie CSRF Aura assente in auraConfig ({pagina})"
            )
        return nome_cookie

    def _estrai_token_aura_login(self, html: str) -> str:
        """Token CSRF della pagina login dal cookie indicato in auraConfig.

        Verificato su aura_prod.js con REA:
            a.token ? YK($A.d, a.token) : a.eikoocnekot && YK($A.d, ZK(a.eikoocnekot)),
            a.ConnectCSRFToken && ($A.d.ix = a.ConnectCSRFToken)
        aura.token ($A.d.Ec) viene valorizzato SOLO da 'token' o dal cookie
        indicato da 'eikoocnekot'; ConnectCSRFToken ($A.d.ix) appartiene
        invece a getConnectCsrfToken() per la Connect REST API e NON viene
        mai inviato come aura.token. Quando exposeCsrfToken è false e non
        c'è eikoocnekot (come su *.my.site.com), $A.d.Ec resta null ('null').
        """
        cfg = self._estrai_aura_config_dict(html, "login")
        nome_cookie = cfg.get("eikoocnekot") or cfg.get("token")
        if nome_cookie:
            return self._aura_cookie_token(nome_cookie)
        raise ParsingError("Token CSRF Aura assente in auraConfig (login)")

    @classmethod
    def _estrai_aura_config(cls, html: str) -> tuple[str, str]:
        """(aura.context serializzato, nome del cookie CSRF) dalla pagina.

        auraConfig.eikoocnekot ('tokenCookie' al contrario) è il NOME del
        cookie che contiene il token CSRF: il valore da passare come
        aura.token va letto dal cookie jar della sessione.
        """
        cfg = cls._estrai_aura_config_dict(html, "gse-terna")
        try:
            ctx = cfg["context"]
            context = json.dumps(
                {
                    "mode": "PROD",
                    "fwuid": ctx["fwuid"],
                    "app": "siteforce:communityApp",
                    "loaded": ctx["loaded"],
                    "dn": [],
                    "globals": {},
                    "uad": True,
                }
            )
        except (KeyError, TypeError) as err:
            raise ParsingError(f"auraConfig irriconoscibile: {err}") from err
        return context, cls._estrai_nome_cookie_aura(html, "gse-terna")

    def _aura_cookie_token(self, nome_cookie: str) -> str:
        """Valore del cookie CSRF il cui nome è indicato da auraConfig."""
        for cookie in self._session.cookie_jar:
            if cookie.key == nome_cookie:
                return cookie.value
        raise ParsingError(
            f"Cookie CSRF Aura '{nome_cookie}' assente dalla sessione"
        )

    async def _aura_action(self, descriptor: str, params: dict, caller: str) -> list:
        """POST di una singola azione Aura; ritorna il returnValue."""
        message = json.dumps(
            {
                "actions": [
                    {
                        "id": "1;a",
                        "descriptor": descriptor,
                        "callingDescriptor": caller,
                        "params": params,
                        "longRunning": True,
                    }
                ]
            }
        )
        data = {
            "message": message,
            "aura.context": self._aura_context or "",
            "aura.pageURI": "/s/gse-terna",
            "aura.token": self._aura_token or "",
        }
        headers = {
            "User-Agent": _BROWSER_USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": self._origine,
            "Referer": self._su_host(GSE_TERNA_PAGE_URL),
        }
        async with self._session.post(
            self._su_host(AURA_ENDPOINT), data=data, headers=headers
        ) as resp:
            testo = await _leggi_testo(resp)
            resp.raise_for_status()
        if "invalidSession" in testo or "invalid_csrf" in testo:
            raise AuraSessionScaduta(
                "Sessione web Aura scaduta o token CSRF invalido"
            )
        try:
            azione = json.loads(testo)["actions"][0]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as err:
            raise ParsingError(
                f"Risposta Aura non riconosciuta: {testo[:200]!r}"
            ) from err
        if azione.get("state") != "SUCCESS":
            raise ParsingError(
                f"Azione Aura {descriptor} fallita: stato {azione.get('state')!r}"
            )
        return azione.get("returnValue") or []

    # -- Scraping HTML/JSON --------------------------------------------------
    # Le parti più probabilmente da correggere contro una HAR fresca.

    @staticmethod
    def _estrai_fwuid(html: str) -> str:
        # Forma diretta: "fwuid":"<value>" letterale in JSON/JS incorporato.
        match = re.search(r'"fwuid"\s*:\s*"([^"]+)"', html)
        if match:
            return match.group(1)

        # Forma percent-encoded: confermato su cattura reale, il blob di
        # contesto Aura è incorporato direttamente nel PATH dell'URL di uno
        # <script src="...">, non in una variabile JS:
        #   <script src="/PortaleClienti/s/sfsites/l/%7B%22mode%22...
        #     %22fwuid%22%3A%22<value>%22...%7D/app.js">
        # Deve essere così perché virgolette letterali dentro un attributo
        # src="..." romperebbero il parsing HTML.
        match = re.search(r"%22fwuid%22%3A%22([^%]+)%22", html)
        if match:
            return match.group(1)

        raise ParsingError("fwuid non trovato sulla pagina di login")

    @staticmethod
    def _estrai_loaded(html: str) -> str:
        """Estrae il valore grezzo (JSON, come stringa) del campo 'loaded'
        dallo stesso blob di bootstrap da cui si estrae fwuid - es.
        '{"APPLICATION@markup://siteforce:loginApp2":"1628_TW-..."}'.

        Necessario perché aura.context con 'loaded':{} (vuoto) viene
        rifiutato dal server con un AuraClientInputException generico,
        confermato confrontando con una richiesta loginUser reale riuscita:
        il valore reale di 'loaded' non è vuoto e va riportato identico.

        Ritorna '{}' (stringa) se non trovato, così il chiamante degrada al
        comportamento precedente invece di fallire qui - il fallimento vero
        arriverà comunque dal server sulla loginUser, con l'errore già
        diagnosticato da lì.
        """
        match = re.search(r'"loaded"\s*:\s*(\{[^}]*\})', html)
        if match:
            return match.group(1)

        match = re.search(r"%22loaded%22%3A(%7B.*?%7D)", html)
        if match:
            return unquote(match.group(1))

        return "{}"

    @staticmethod
    def _estrai_url_redirect_js(html: str) -> str:
        """La pagina di frontdoor.jsp è un ponte che rimanda al vero form
        OTP con window.location.replace('URL') (JavaScript, non un redirect
        HTTP) - un browser lo segue da solo, qui va estratto a mano e
        richiesto con una GET esplicita.

        L'URL dentro replace() è già assoluto e correttamente
        percent-encoded (è dentro una stringa JS, non un attributo HTML),
        quindi nessun problema di doppia codifica come altrove in questo
        file - va usato così com'è.
        """
        match = re.search(r"window\.location\.replace\('([^']+)'\)", html)
        if match:
            return match.group(1)

        # Fallback: alcune varianti di questa pagina Salesforce usano
        # window.location.href invece di .replace(...).
        match = re.search(r"window\.location\.href\s*=\s*'([^']+)'", html)
        if match:
            return match.group(1)

        _log_parsing_failure_context(html, "window.location.replace(...) su pagina frontdoor")
        raise ParsingError(
            "Redirect JavaScript verso il form OTP non trovato sulla pagina "
            f"di frontdoor (pagina lunga {len(html)} caratteri - vedi log "
            "per un'anteprima)"
        )

    def _analizza_pagina_otp(self, html: str) -> None:
        """Estrae dalla pagina Visualforce del form OTP tutto ciò che serve
        per sottometterlo (ViewState/CSRF + nomi dinamici dei campi),
        salvandolo in self._flow."""

        def trova(nome_campo: str) -> str:
            # Cerca l'intero tag <input ...> che contiene questo attributo
            # 'name', poi 'value' AL SUO INTERNO - indipendente dall'ordine
            # in cui i due attributi compaiono nel tag.
            tag_match = re.search(rf'<input[^>]*name="{re.escape(nome_campo)}"[^>]*>', html)
            if not tag_match:
                _log_parsing_failure_context(html, nome_campo)
                raise ParsingError(
                    f"Campo '{nome_campo}' non trovato sulla pagina OTP "
                    f"(pagina lunga {len(html)} caratteri - vedi log per un'anteprima)"
                )
            value_match = re.search(r'value="([^"]*)"', tag_match.group(0))
            if not value_match:
                raise ParsingError(
                    f"Campo '{nome_campo}' trovato ma senza attributo 'value' "
                    f"leggibile: {tag_match.group(0)!r}"
                )
            return value_match.group(1)

        self._flow.view_state = trova("com.salesforce.visualforce.ViewState")
        self._flow.view_state_version = trova("com.salesforce.visualforce.ViewStateVersion")
        self._flow.view_state_mac = trova("com.salesforce.visualforce.ViewStateMAC")
        self._flow.view_state_csrf = trova("com.salesforce.visualforce.ViewStateCSRF")

        # I prefissi dei campi sotto sono generati da Salesforce e possono
        # cambiare tra deploy: si tenta di scoprirli dinamicamente invece di
        # fidarsi solo dei default hardcoded (usati come fallback sopra).
        otp_field = re.search(r'name="([^"]*OTP_Input[^"]*)"', html)
        if otp_field:
            self._flow.otp_field_name = otp_field.group(1)

        # La pagina ha DUE campi con "Richiedi_nuovo_OTP" nel nome: una
        # checkbox visibile (element___input____...) e un campo nascosto che
        # la specchia (element___hidden____...), aggiornato da un onclick
        # JS - è quest'ultimo che va sottomesso. Un regex generico trova per
        # primo la checkbox (appare prima nell'HTML), causando l'invio del
        # campo sbagliato: confermato su una risposta reale, dove il server
        # trattava la sottomissione del codice come un'ennesima richiesta di
        # reinvio invece che una convalida.
        resend_field = re.search(
            r'name="([^"]*element___hidden____Richiedi_nuovo_OTP[^"]*)"', html
        )
        if resend_field:
            self._flow.resend_field_name = resend_field.group(1)
        resend_checkbox = re.search(
            r'name="([^"]*element___input____Richiedi_nuovo_OTP[^"]*)"', html
        )
        if resend_checkbox:
            self._flow.resend_checkbox_field_name = resend_checkbox.group(1)
        next_field = re.search(r'name="([^"]*nextAjax[^"]*)"', html)
        if next_field:
            self._flow.next_field_name = next_field.group(1)

        form_action = re.search(r'<form[^>]+action="([^"]+)"', html)
        if form_action:
            action = form_action.group(1)
            self._flow.form_action_url = self._su_host(
                action if action.startswith("http") else f"{self._origine}{action}"
            )
