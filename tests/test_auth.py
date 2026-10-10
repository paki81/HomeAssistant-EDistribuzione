"""Test per auth.py: parsing HTML/regex e logica pura, nessuna chiamata di
rete reale (solo sessioni finte in memoria).

auth.py di per sé non dipende da Home Assistant (solo aiohttp e libreria
standard), ma __init__.py del pacchetto sì (importa homeassistant.config_entries).
Per poterlo testare in isolamento (più veloce, e verificabile anche senza
homeassistant installato) questo file carica const.py e auth.py DIRETTAMENTE
via importlib, bypassando __init__.py - lo stesso trucco usato da
scripts/verify_login.py.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path

import aiohttp
import pytest

PKG_DIR = Path(__file__).parent.parent / "custom_components" / "edistribuzione"


def _load_auth_module():
    pkg_name = "edistribuzione_test_auth"
    if f"{pkg_name}.auth" in sys.modules:
        return sys.modules[f"{pkg_name}.auth"]

    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = [str(PKG_DIR)]
    sys.modules[pkg_name] = pkg

    def _load(modname: str, filename: str):
        spec = importlib.util.spec_from_file_location(f"{pkg_name}.{modname}", PKG_DIR / filename)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[f"{pkg_name}.{modname}"] = mod
        spec.loader.exec_module(mod)
        return mod

    _load("const", "const.py")
    return _load("auth", "auth.py")


auth = _load_auth_module()


# ---------------------------------------------------------------------------
# _estrai_fwuid
# ---------------------------------------------------------------------------


class TestEstraiFwuid:
    def test_forma_diretta(self):
        html = '<script>var ctx = {"mode":"PROD","fwuid":"ABC123"};</script>'
        assert auth.AuthClient._estrai_fwuid(html) == "ABC123"

    def test_forma_percent_encoded(self):
        """Confermato su una cattura reale: il fwuid è incorporato
        percent-encoded nel path di un URL di bootstrap, non in una
        variabile JS in chiaro."""
        html = (
            '<script src="/PortaleClienti/s/sfsites/l/%7B%22mode%22%3A%22PROD%22'
            '%2C%22fwuid%22%3A%22XYZ789%22%2C%22loaded%22%3A%7B%7D%7D/app.js">'
            "</script>"
        )
        assert auth.AuthClient._estrai_fwuid(html) == "XYZ789"

    def test_non_trovato_solleva_errore(self):
        with pytest.raises(auth.ParsingError):
            auth.AuthClient._estrai_fwuid("<html>niente qui</html>")


# ---------------------------------------------------------------------------
# _estrai_loaded
# ---------------------------------------------------------------------------


class TestEstraiLoaded:
    def test_forma_diretta(self):
        html = '{"loaded":{"APPLICATION@markup://siteforce:loginApp2":"123"}}'
        assert (
            auth.AuthClient._estrai_loaded(html)
            == '{"APPLICATION@markup://siteforce:loginApp2":"123"}'
        )

    def test_forma_percent_encoded(self):
        """Stesso blob percent-encoded di _estrai_fwuid: 'loaded' contiene un
        riferimento alla versione del componente caricato, necessario perché
        aura.context con 'loaded':{} vuoto viene rifiutato dal server
        (AuraClientInputException)."""
        html = (
            "%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce"
            "%3AloginApp2%22%3A%221628_TW-5Qu0N5YI_dQXZ9Cqalw%22%7D"
        )
        risultato = auth.AuthClient._estrai_loaded(html)
        assert risultato == (
            '{"APPLICATION@markup://siteforce:loginApp2":"1628_TW-5Qu0N5YI_dQXZ9Cqalw"}'
        )

    def test_fallback_oggetto_vuoto_se_non_trovato(self):
        """Non solleva errore: degrada a '{}' e lascia che sia il server a
        segnalare il problema (già diagnosticato altrove)."""
        assert auth.AuthClient._estrai_loaded("<html>niente</html>") == "{}"


# ---------------------------------------------------------------------------
# _estrai_url_redirect_js
# ---------------------------------------------------------------------------


class TestEstraiUrlRedirectJs:
    def test_window_location_replace(self):
        html = "<script>window.location.replace('https://example.com/target?a=1&b=2');</script>"
        assert (
            auth.AuthClient._estrai_url_redirect_js(html)
            == "https://example.com/target?a=1&b=2"
        )

    def test_window_location_href_variante(self):
        html = "<script>window.location.href = 'https://example.com/other';</script>"
        assert auth.AuthClient._estrai_url_redirect_js(html) == "https://example.com/other"

    def test_non_trovato_solleva_errore(self):
        with pytest.raises(auth.ParsingError):
            auth.AuthClient._estrai_url_redirect_js("<html>niente qui</html>")


# ---------------------------------------------------------------------------
# _analizza_pagina_otp
# ---------------------------------------------------------------------------


class TestAnalizzaPaginaOtp:
    """Il gruppo più importante: copre in particolare la regressione del
    campo Richiedi_nuovo_OTP (checkbox vs hidden), che ha richiesto diversi
    round di debug con dati reali per essere trovata."""

    HTML_PAGINA_OTP = """
    <html><body>
      <input type="hidden" name="com.salesforce.visualforce.ViewState" value="VS123" />
      <input type="hidden" name="com.salesforce.visualforce.ViewStateVersion" value="VSV456" />
      <input type="hidden" name="com.salesforce.visualforce.ViewStateMAC" value="VSM789" />
      <input type="hidden" name="com.salesforce.visualforce.ViewStateCSRF" value="VSC000" />
      <input id="thePage:j_id2:i:f:pb:d:OTP_Input.input"
             name="thePage:j_id2:i:f:pb:d:element___input____OTP_Input"
             type="text" value="" />
      <input id="thePage:j_id2:i:f:pb:d:Richiedi_nuovo_OTP.input"
             name="thePage:j_id2:i:f:pb:d:element___input____Richiedi_nuovo_OTP"
             type="checkbox" value="true" />
      <input type="hidden"
             id="thePage:j_id2:i:f:pb:d:element___hidden____Richiedi_nuovo_OTP"
             name="thePage:j_id2:i:f:pb:d:element___hidden____Richiedi_nuovo_OTP"
             value="false" />
    </body></html>
    """

    @staticmethod
    def _client():
        return auth.AuthClient(session=None)

    def test_estrae_tutti_i_campi_viewstate(self):
        client = self._client()
        client._analizza_pagina_otp(self.HTML_PAGINA_OTP)
        assert client._flow.view_state == "VS123"
        assert client._flow.view_state_version == "VSV456"
        assert client._flow.view_state_mac == "VSM789"
        assert client._flow.view_state_csrf == "VSC000"

    def test_resend_field_e_il_campo_hidden_non_la_checkbox(self):
        """L'estrazione deve prendere il campo nascosto
        (element___hidden____Richiedi_nuovo_OTP), non la checkbox visibile:
        sbagliando qui il server tratta ogni submit come un'ennesima
        richiesta di reinvio invece che una convalida del codice."""
        client = self._client()
        client._analizza_pagina_otp(self.HTML_PAGINA_OTP)
        assert client._flow.resend_field_name == (
            "thePage:j_id2:i:f:pb:d:element___hidden____Richiedi_nuovo_OTP"
        )
        assert "input____Richiedi_nuovo_OTP" not in client._flow.resend_field_name

    def test_ordine_attributi_invertito_nel_tag(self):
        """Il regex non deve assumere 'name' sempre prima di 'value' nel
        tag: se l'ordine è invertito (value poi name), deve funzionare
        comunque."""
        html_invertito = (
            '<input type="hidden" value="VS_INVERTITO" '
            'name="com.salesforce.visualforce.ViewState" />'
        )
        client = self._client()
        # Solo il primo campo è presente: l'estrazione del secondo fallirà,
        # ma vogliamo verificare che il PRIMO sia stato letto correttamente
        # nonostante l'ordine invertito degli attributi.
        with pytest.raises(auth.ParsingError):
            client._analizza_pagina_otp(html_invertito)
        assert client._flow.view_state == "VS_INVERTITO"

    def test_campo_mancante_solleva_errore_con_nome_campo(self):
        client = self._client()
        with pytest.raises(auth.ParsingError, match="ViewState"):
            client._analizza_pagina_otp("<html><title>Sessione scaduta</title></html>")

    def test_cattura_anche_la_checkbox_di_reinvio(self):
        """La checkbox visibile serve per il reinvio esplicito del codice
        (async_resend_otp), dove riproduciamo il submit di un browser con la
        casella spuntata - il campo hidden da solo non basta a rappresentarlo."""
        client = self._client()
        client._analizza_pagina_otp(self.HTML_PAGINA_OTP)
        assert client._flow.resend_checkbox_field_name == (
            "thePage:j_id2:i:f:pb:d:element___input____Richiedi_nuovo_OTP"
        )


# ---------------------------------------------------------------------------
# _form_invio_iniziale / _form_richiedi_nuovo / _form_convalida
# (i tre costruttori di payload del form OTP)
# ---------------------------------------------------------------------------


class TestCostruttoriFormOtp:
    @staticmethod
    def _client():
        client = auth.AuthClient(session=None)
        client._analizza_pagina_otp(TestAnalizzaPaginaOtp.HTML_PAGINA_OTP)
        return client

    def test_invio_iniziale_senza_codice_ne_flag_di_reinvio(self):
        """Il primo submit serve solo a far spedire il codice: non deve
        contenere né un OTP da convalidare né il flag di reinvio."""
        dati = self._client()._form_invio_iniziale()
        assert not [k for k in dati if "OTP_Input" in k]
        assert not [k for k in dati if "Richiedi_nuovo_OTP" in k]
        assert dati["com.salesforce.visualforce.ViewState"] == "VS123"

    def test_convalida_codice_manda_hidden_a_false(self):
        """Con il flag di reinvio a 'true' il server tratterebbe la
        convalida come un'ennesima richiesta di nuovo codice."""
        dati = self._client()._form_convalida("12345")
        assert dati["thePage:j_id2:i:f:pb:d:element___input____OTP_Input"] == "12345"
        assert dati["thePage:j_id2:i:f:pb:d:element___hidden____Richiedi_nuovo_OTP"] == "false"

    def test_reinvio_manda_hidden_e_checkbox_a_true_senza_codice(self):
        dati = self._client()._form_richiedi_nuovo()
        assert dati["thePage:j_id2:i:f:pb:d:element___hidden____Richiedi_nuovo_OTP"] == "true"
        assert dati["thePage:j_id2:i:f:pb:d:element___input____Richiedi_nuovo_OTP"] == "true"
        assert not [k for k in dati if "OTP_Input" in k]


# ---------------------------------------------------------------------------
# Invio / reinvio del codice: conferma e limite di sessioni
# ---------------------------------------------------------------------------


class _RispostaFinta:
    status = 200

    def __init__(self, body: str) -> None:
        self._body = body

    async def text(self) -> str:
        return self._body

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                request_info=None, history=(), status=self.status
            )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info) -> bool:
        return False


class _SessioneFinta:
    """Minimo indispensabile per _async_post_form_otp: registra i dati
    inviati e restituisce sempre la stessa pagina."""

    def __init__(self, body: str) -> None:
        self._body = body
        self.dati_inviati: dict | None = None

    def post(self, url, data=None, headers=None):
        self.dati_inviati = data
        return _RispostaFinta(self._body)


PAGINA_OTP_CON_CONFERMA = (
    "<html><body><p>Abbiamo inviato un codice a 5 cifre al tuo indirizzo email</p>"
    + TestAnalizzaPaginaOtp.HTML_PAGINA_OTP
    + "</body></html>"
)


def _client_su_form_otp(body: str):
    session = _SessioneFinta(body)
    client = auth.AuthClient(session)
    client._analizza_pagina_otp(TestAnalizzaPaginaOtp.HTML_PAGINA_OTP)
    return client, session


class TestInvioOtp:
    async def test_conferma_invio_riconosciuta(self):
        client, _ = _client_su_form_otp(PAGINA_OTP_CON_CONFERMA)
        await client._async_avvia_invio_otp()
        assert client.otp_invio_confermato is True

    async def test_invio_non_confermato_non_e_fatale_ma_viene_segnalato(
        self, caplog, monkeypatch, tmp_path
    ):
        """Se la pagina non contiene nessuno dei messaggi di conferma noti il
        flusso continua (la formulazione potrebbe essere solo diversa), ma
        resta traccia nei log e il flag permette al config flow di
        avvisare."""
        # Il dump di debug viene scritto nella cwd: lo dirottiamo su tmp_path
        # per non lasciare otp_send_debug.html dentro il repository.
        monkeypatch.chdir(tmp_path)
        client, _ = _client_su_form_otp(TestAnalizzaPaginaOtp.HTML_PAGINA_OTP)
        await client._async_avvia_invio_otp()
        assert client.otp_invio_confermato is False
        assert "non ha confermato l'invio" in caplog.text
        # Il dump e' scritto in un executor (per non bloccare l'event loop
        # di Home Assistant), quindi puo' non esistere ancora al ritorno.
        dump = tmp_path / "otp_send_debug.html"
        for _ in range(50):
            if dump.exists():
                break
            await asyncio.sleep(0.02)
        assert dump.exists()

    async def test_pagina_limite_sessioni_solleva_eccezione_dedicata(self, monkeypatch, tmp_path):
        """Con troppe sessioni aperte nessun codice viene spedito: va
        distinto da un OTP sbagliato o da un cambio di markup, altrimenti
        l'utente resta ad aspettare un codice che non arriverà mai."""
        monkeypatch.chdir(tmp_path)
        client, _ = _client_su_form_otp(
            "<html><body>Hai superato il numero di sessioni simultanee "
            "consentite</body></html>"
        )
        with pytest.raises(auth.TroppeSessioni):
            await client._async_avvia_invio_otp()

    async def test_resend_otp_invia_il_flag_di_reinvio(self):
        client, session = _client_su_form_otp(PAGINA_OTP_CON_CONFERMA)
        assert await client.async_resend_otp() is True
        assert (
            session.dati_inviati["thePage:j_id2:i:f:pb:d:element___hidden____Richiedi_nuovo_OTP"]
            == "true"
        )

    async def test_resend_otp_prima_del_login_e_un_errore(self):
        client = auth.AuthClient(session=None)
        with pytest.raises(auth.AuthError, match="async_begin_login"):
            await client.async_resend_otp()


# ---------------------------------------------------------------------------
# Schermata di consenso OAuth
# ---------------------------------------------------------------------------


# Struttura ricalcata sulla pagina reale: titolo "Consentire l'accesso?", un
# solo form con 8 campi hidden e DUE pulsanti submit con lo stesso
# name="save", distinguibili solo per il valore - "Consenti" approva, " Nega "
# (con gli spazi) rifiuta.
HTML_PAGINA_CONSENSO = """
<html><head><title>Consentire l'accesso? | Portale Clienti</title></head>
<body>
  <form id="editPage" method="post"
        action="/PortaleClienti/_ui/identity/oauth/ui/AuthorizationPage">
    <input type="hidden" name="_CONFIRMATIONTOKEN" value="TOKEN123" />
    <input type="hidden" name="cancelURL" value="/PortaleClienti/home/home.jsp" />
    <input type="hidden" name="retURL" value="/PortaleClienti/home/home.jsp" />
    <input type="hidden" name="save_new_url"
           value="/services/oauth2/approval?a=1&amp;b=2&amp;c=l&#39;app" />
    <input type="hidden" name="source" value="SORGENTE456" />
    <input type="hidden" name="scope_hint" value="web api openid" />
    <input type="hidden" name="authPageHint" value="HINT789" />
    <input type="hidden" name="display" value="touch" />
    <input type="submit" name="save" value="Consenti" class="button primary" />
    <input type="submit" name="save" value=" Nega " id="oadeny" />
  </form>
</body></html>
"""


class TestFormConsenso:
    def test_seleziona_consenti_e_non_nega(self):
        """I due pulsanti hanno lo stesso name: prendere quello sbagliato
        significherebbe NEGARE l'autorizzazione all'integrazione."""
        action, dati = _client_su_host("edistribuzione.my.site.com")._estrai_form_consenso(
            HTML_PAGINA_CONSENSO
        )
        assert dati["save"] == "Consenti"
        assert action == (
            "https://edistribuzione.my.site.com/PortaleClienti/_ui/identity/oauth/ui/AuthorizationPage"
        )

    def test_rimanda_tutti_i_campi_hidden_deescapati(self):
        """save_new_url e source sono URL pieni di parametri: se restano
        escapati (&amp;) il server riceve valori diversi da quelli che ha
        generato."""
        _, dati = _client_su_host("edistribuzione.my.site.com")._estrai_form_consenso(
            HTML_PAGINA_CONSENSO
        )
        assert set(dati) == {
            "_CONFIRMATIONTOKEN",
            "cancelURL",
            "retURL",
            "save_new_url",
            "source",
            "scope_hint",
            "authPageHint",
            "display",
            "save",
        }
        assert dati["save_new_url"] == "/services/oauth2/approval?a=1&b=2&c=l'app"

    def test_pagina_senza_pulsante_di_consenso_ritorna_none(self):
        """Su una pagina che non è una schermata di consenso il chiamante
        deve poter proseguire col suo errore di parsing abituale."""
        assert (
            _client_su_host("edistribuzione.my.site.com")._estrai_form_consenso(
                "<html><body><form><input type='submit' name='x' value='Invia'>"
                "</form></body></html>"
            )
            is None
        )


class _RispostaConLocation(_RispostaFinta):
    def __init__(self, body: str, location: str | None = None) -> None:
        super().__init__(body)
        self.headers = {"Location": location} if location else {}


class _SessioneACoda:
    """Restituisce le risposte in coda, una per chiamata (get o post), e
    registra i payload inviati."""

    def __init__(self, risposte: list) -> None:
        self._risposte = list(risposte)
        self.post_inviati: list[dict] = []
        # Imita il cookie jar di aiohttp: iterabile di oggetti con
        # attributi .key/.value (Morsel).
        self.cookie_jar: list = []

    def _prossima(self):
        return self._risposte.pop(0)

    def post(self, url, data=None, headers=None, allow_redirects=None):
        self.post_inviati.append({"url": url, "data": data})
        return self._prossima()

    def get(self, url, headers=None, params=None):
        return self._prossima()


class TestApprovazioneConsenso:
    async def test_preme_consenti_e_recupera_il_codice(self):
        """Dopo l'OTP arriva la schermata di consenso invece del codice;
        premendo "Consenti" il codice arriva nel Location del redirect verso
        lo schema custom dell'app (eneldist://), che aiohttp non può
        seguire."""
        session = _SessioneACoda([
            _RispostaConLocation(
                "eneldist://redirect?code=CODICE_OK&state=S",
                location="eneldist://redirect?code=CODICE_OK&state=S",
            )
        ])
        client = auth.AuthClient(session)
        risultato = await client._async_approva_consenso(HTML_PAGINA_CONSENSO)
        assert "code=CODICE_OK" in risultato
        assert session.post_inviati[0]["data"]["save"] == "Consenti"
        assert session.post_inviati[0]["url"].endswith("/AuthorizationPage")

    async def test_senza_form_di_consenso_ritorna_none(self):
        client = auth.AuthClient(_SessioneACoda([]))
        assert await client._async_approva_consenso("<html>niente</html>") is None


# ---------------------------------------------------------------------------
# _verifica_non_troppe_sessioni (centralizzata: era duplicata in tre punti)
# ---------------------------------------------------------------------------


class TestVerificaNonTroppeSessioni:
    def test_nessun_marcatore_non_solleva(self):
        auth.AuthClient._verifica_non_troppe_sessioni("tutto normale qui")

    def test_marcatore_presente_solleva(self):
        with pytest.raises(auth.TroppeSessioni):
            auth.AuthClient._verifica_non_troppe_sessioni(
                "Hai superato il numero di sessioni simultanee consentite"
            )

    def test_salva_il_dump_solo_se_richiesto(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(auth.TroppeSessioni):
            auth.AuthClient._verifica_non_troppe_sessioni(
                "sessioni contemporanee superate", "dump.html"
            )
        assert (tmp_path / "dump.html").exists()


# ---------------------------------------------------------------------------
# _su_host: gli URL assoluti che il server genera sull'ALTRO host della
# stessa org Salesforce vengono riscritti sull'host attivo del client
# (in entrambe le direzioni), altrimenti seguirli ricadrebbe nella
# verifica antibot di Imperva.
# ---------------------------------------------------------------------------


def _client_su_host(host: str):
    client = auth.AuthClient(None)
    client._host = host
    return client


class TestSuHost:
    def test_riscrive_il_dominio_protetto_sul_diretto(self):
        """Con l'host diretto attivo, seguire un URL su
        private.e-distribuzione.it riporterebbe dentro la verifica antibot
        "Pardon Our Interruption"."""
        client = _client_su_host("edistribuzione.my.site.com")
        assert client._su_host(
            "https://private.e-distribuzione.it/PortaleClienti/secur/frontdoor.jsp?retURL=x"
        ) == "https://edistribuzione.my.site.com/PortaleClienti/secur/frontdoor.jsp?retURL=x"

    def test_riscrive_il_diretto_sul_primario(self):
        """La riscrittura vale anche in senso inverso: con il primario
        attivo, un URL generato dal server su *.my.site.com va riportato
        sul dominio ufficiale."""
        client = _client_su_host("private.e-distribuzione.it")
        assert client._su_host(
            "https://edistribuzione.my.site.com/PortaleClienti/loginflow/loginFlow.apexp"
        ) == "https://private.e-distribuzione.it/PortaleClienti/loginflow/loginFlow.apexp"

    def test_lascia_invariato_l_url_gia_sull_host_attivo(self):
        client = _client_su_host("edistribuzione.my.site.com")
        url = "https://edistribuzione.my.site.com/PortaleClienti/loginflow/loginFlow.apexp"
        assert client._su_host(url) == url

    def test_lascia_invariati_altri_host_e_relativi(self):
        """Solo i due host della stessa org vanno riscritti: un hostname
        diverso passa com'è, e un path relativo resta relativo per il join
        del chiamante."""
        client = _client_su_host("private.e-distribuzione.it")
        assert client._su_host("https://example.com/x") == "https://example.com/x"
        assert (
            client._su_host("/PortaleClienti/loginflow/loginFlow.apexp")
            == "/PortaleClienti/loginflow/loginFlow.apexp"
        )


# ---------------------------------------------------------------------------
# Gerarchia eccezioni
# ---------------------------------------------------------------------------


class TestGerarchiaEccezioni:
    def test_invalid_credentials_e_sottoclasse_di_auth_error(self):
        assert issubclass(auth.InvalidCredentials, auth.AuthError)

    def test_invalid_otp_e_sottoclasse_di_auth_error(self):
        assert issubclass(auth.InvalidOtp, auth.AuthError)

    def test_parsing_error_e_sottoclasse_di_auth_error(self):
        assert issubclass(auth.ParsingError, auth.AuthError)

    def test_troppe_sessioni_e_sottoclasse_di_auth_error_ma_non_di_credenziali(self):
        """Deve essere gestibile a parte: le credenziali sono corrette, è
        l'account ad avere troppe sessioni aperte."""
        assert issubclass(auth.TroppeSessioni, auth.AuthError)
        assert not issubclass(auth.TroppeSessioni, auth.InvalidCredentials)


# ---------------------------------------------------------------------------
# Verifica antibot di Imperva al posto delle pagine attese
# ---------------------------------------------------------------------------

PAGINA_ANTIBOT = (
    "<html><head><title>Pardon Our Interruption</title></head><body>"
    "<p>As you were browsing something about your browser made us think you were a bot.</p>"
    '<script src="/_Incapsula_Resource?SWJIYLWA=abc"></script></body></html>'
)


class _RispostaToken(_RispostaFinta):
    def __init__(self, body: str, status: int = 200) -> None:
        super().__init__(body)
        self.status = status


class TestAccessoBloccato:
    @pytest.mark.parametrize(
        "pagina",
        [PAGINA_ANTIBOT, "<html>Request unsuccessful. Incapsula incident ID: 123-456</html>"],
    )
    def test_riconosce_la_verifica_e_il_blocco(self, pagina):
        with pytest.raises(auth.AccessoBloccato):
            auth._verifica_non_bloccato(pagina)

    def test_lo_script_di_imperva_in_una_pagina_normale_non_e_un_blocco(self):
        """Imperva inserisce _Incapsula_Resource anche nelle pagine normali
        di un sito protetto: da solo non deve bloccare un login valido."""
        auth._verifica_non_bloccato(
            '<html><title>Login</title><script src="/_Incapsula_Resource?x=1"></script></html>'
        )

    def test_e_un_auth_error(self):
        assert issubclass(auth.AccessoBloccato, auth.AuthError)

    async def test_refresh_del_token_bloccato_su_entrambi_gli_host(self):
        """AccessoBloccato arriva al chiamante solo quando anche il ripiego
        sull'host diretto trova la pagina antibot."""
        session = _SessioneACoda([_RispostaToken(PAGINA_ANTIBOT), _RispostaToken(PAGINA_ANTIBOT)])
        with pytest.raises(auth.AccessoBloccato):
            await auth.AuthClient(session).async_refresh_access_token("rt")

    async def test_refresh_ripiega_sul_host_diretto_se_il_primario_e_bloccato(self):
        """Primario dietro antibot: il refresh ripete sulla stessa org al
        dominio diretto e riesce. Le due richieste devono andare su host
        diversi."""
        session = _SessioneACoda([
            _RispostaToken(PAGINA_ANTIBOT),
            _RispostaToken('{"access_token": "nuovo"}'),
        ])
        tokens = await auth.AuthClient(session).async_refresh_access_token("rt")
        assert tokens.access_token == "nuovo"
        assert "private.e-distribuzione.it" in session.post_inviati[0]["url"]
        assert "edistribuzione.my.site.com" in session.post_inviati[1]["url"]

    async def test_refresh_usa_il_primario_senza_ripieghi(self):
        """In condizioni normali una sola richiesta, sul dominio ufficiale:
        il ripiego non deve lasciare il client ancorato all'host diretto."""
        session = _SessioneACoda([_RispostaToken('{"access_token": "nuovo"}')])
        tokens = await auth.AuthClient(session).async_refresh_access_token("rt")
        assert tokens.access_token == "nuovo"
        assert len(session.post_inviati) == 1
        assert "private.e-distribuzione.it" in session.post_inviati[0]["url"]

    async def test_refresh_con_una_pagina_html_qualunque_e_un_parsing_error(self):
        session = _SessioneACoda([_RispostaToken("<html>manutenzione</html>")])
        with pytest.raises(auth.ParsingError):
            await auth.AuthClient(session).async_refresh_access_token("rt")

    async def test_refresh_riuscito_tiene_il_vecchio_refresh_token(self):
        session = _SessioneACoda([_RispostaToken('{"access_token": "nuovo"}')])
        tokens = await auth.AuthClient(session).async_refresh_access_token("rt")
        assert (tokens.access_token, tokens.refresh_token) == ("nuovo", "rt")

    async def test_invio_otp_bloccato(self):
        client, _ = _client_su_form_otp(PAGINA_ANTIBOT)
        with pytest.raises(auth.AccessoBloccato):
            await client._async_avvia_invio_otp()


# ---------------------------------------------------------------------------
# Form di cambio password (account con password scaduta)
# ---------------------------------------------------------------------------

PAGINA_CAMBIO_PASSWORD = (
    "<html><head><title>Modifica la password</title></head><body>"
    "<p>La tua password è scaduta, impostane una nuova.</p>"
    '<input type="password" name="thePage:j_id2:i:f:pb:d:element___input____NewPassword" />'
    "</body></html>"
)


class TestPasswordScaduta:
    def test_riconosce_il_form_di_cambio_password(self):
        with pytest.raises(auth.PasswordScaduta):
            auth._verifica_non_password_scaduta(PAGINA_CAMBIO_PASSWORD)

    def test_pagina_otp_normale_non_solleva(self):
        """La pagina OTP non deve essere scambiata per un cambio password:
        marcatori valutati solo sulle varianti osservate, non su 'password'
        generico (presente anche in testo innocuo)."""
        auth._verifica_non_password_scaduta(TestAnalizzaPaginaOtp.HTML_PAGINA_OTP)

    def test_e_un_auth_error_ma_non_credenziali(self):
        """Le credenziali sono state accettate: non e' InvalidCredentials,
        l'azione corretta e' rinnovare la password sul portale."""
        assert issubclass(auth.PasswordScaduta, auth.AuthError)
        assert not issubclass(auth.PasswordScaduta, auth.InvalidCredentials)

    async def test_submit_otp_su_pagina_di_rinnovo_solleva_eccezione_dedicata(self):
        """Caso reale (password scaduta): OTP accettato, ma la risposta e'
        il form di cambio password invece del redirect - prima cadeva nel
        generico otp_exchange_failed."""
        client, _ = _client_su_form_otp(PAGINA_CAMBIO_PASSWORD)
        with pytest.raises(auth.PasswordScaduta):
            await client._async_avvia_invio_otp()


# ---------------------------------------------------------------------------
# Sessione web Aura: tabella 'Misure GSE-TERNA' del portale. Struttura delle
# chiamate verificata su cattura mitmproxy del portale reale.
# ---------------------------------------------------------------------------

AURA_CONFIG_HTML = (
    '<html><head><script>var auraConfig = {'
    '"context":{"fwuid":"FW_TEST",'
    '"loaded":{"APPLICATION@markup://siteforce:communityApp":"x"}},'
    '"contextPath":"/PortaleClienti/s/sfsites",'
    '"eikoocnekot":"__Host-CSRF_TEST"'
    "};</script></head><body>pagina</body></html>"
)


class _CookieFinto:
    """Morsel minimo: l'attributo usato da _aura_cookie_token è .key/.value."""

    def __init__(self, key: str, value: str) -> None:
        self.key = key
        self.value = value


def _risposta_aura(return_value) -> _RispostaFinta:
    return _RispostaFinta(
        json.dumps(
            {"actions": [{"id": "1;a", "state": "SUCCESS", "returnValue": return_value}]}
        )
    )


RIGA_D540 = {
    "producedEnergyF1": 4943.045,
    "producedEnergyF2": 1196.09,
    "producedEnergyF3": 951.067,
    "producedEnergyTot": 7090.202,
    "inputEnergyTot": None,
    "intakeEnergyTot": None,
    "incentiveType": "22",
    "yearMonth": "2026-07",
    "fileName": "D540_001_2026_07_20260813_152428_M_6323.json",
    "dispatchedDate": "2026-08-13T13:24:28.000Z",
    "measureState": "Inviata",
}


def _sessione_gse(righe) -> _SessioneACoda:
    """frontdoor OK, pagina con auraConfig, poi le due azioni Aura."""
    session = _SessioneACoda(
        [
            _RispostaFinta("<html>frontdoor</html>"),
            _RispostaFinta(AURA_CONFIG_HTML),
            _risposta_aura({"data": [{"pods": []}]}),  # callSuppliesByPodId
            _risposta_aura(righe),  # QueryRegulatoryComplianceStatusService
        ]
    )
    session.cookie_jar = [_CookieFinto("__Host-CSRF_TEST", "TOKEN_CSRF_TEST")]
    return session


class TestEstraiAuraConfig:
    def test_estrae_context_e_nome_cookie(self):
        context, nome_cookie = auth.AuthClient._estrai_aura_config(AURA_CONFIG_HTML)
        assert '"fwuid":"FW_TEST"' in context or '"fwuid": "FW_TEST"' in context
        assert nome_cookie == "__Host-CSRF_TEST"

    def test_senza_aura_config_solleva_parsing(self):
        with pytest.raises(auth.ParsingError):
            auth.AuthClient._estrai_aura_config("<html>nessuna config</html>")


class TestAuraCookieToken:
    def test_legge_il_valore_del_cookie(self):
        session = _SessioneACoda([])
        session.cookie_jar = [
            _CookieFinto("sid", "x"),
            _CookieFinto("__Host-CSRF_TEST", "TOKEN_CSRF_TEST"),
        ]
        client = auth.AuthClient(session)
        assert client._aura_cookie_token("__Host-CSRF_TEST") == "TOKEN_CSRF_TEST"

    def test_cookie_assente_solleva_parsing(self):
        client = auth.AuthClient(_SessioneACoda([]))
        with pytest.raises(auth.ParsingError):
            client._aura_cookie_token("__Host-CSRF_TEST")


class TestMisureGseTerna:
    async def test_pipeline_completa_restituisce_le_righe(self):
        session = _sessione_gse([RIGA_D540])
        client = auth.AuthClient(session)
        righe = await client.async_get_misure_gse_terna(
            "ACCESS_TOKEN", "IT001E04193830", "2026-07"
        )
        assert righe == [RIGA_D540]

    async def test_seleziona_il_pod_e_interroga_il_mese(self):
        session = _sessione_gse([RIGA_D540])
        client = auth.AuthClient(session)
        await client.async_get_misure_gse_terna("ACCESS_TOKEN", "IT001E04193830", "2026-07")
        messaggi = [
            json.loads(post["data"]["message"]) for post in session.post_inviati
        ]
        assert "callSuppliesByPodId" in messaggi[0]["actions"][0]["descriptor"]
        assert messaggi[0]["actions"][0]["params"]["pod"] == "IT001E04193830"
        assert "QueryRegulatoryComplianceStatusService" in messaggi[1]["actions"][0][
            "descriptor"
        ]
        assert messaggi[1]["actions"][0]["params"]["YearMonth"] == "2026-07"

    async def test_aura_token_e_il_valore_del_cookie_csrf(self):
        session = _sessione_gse([])
        client = auth.AuthClient(session)
        await client.async_get_misure_gse_terna("ACCESS_TOKEN", "IT001E04193830", "2026-07")
        for post in session.post_inviati:
            assert post["data"]["aura.token"] == "TOKEN_CSRF_TEST"

    async def test_risposta_vuota_restituisce_lista_vuota(self):
        session = _sessione_gse([])
        client = auth.AuthClient(session)
        assert (
            await client.async_get_misure_gse_terna(
                "ACCESS_TOKEN", "ITP0AE04193830", "2026-07"
            )
            == []
        )

    async def test_sessione_aura_scaduta_riapre_e_riprova(self):
        """Prima azione con invalidSession: la sessione web viene riaperta
        (frontdoor + pagina) e le azioni ripetute."""
        session = _SessioneACoda(
            [
                _RispostaFinta("<html>frontdoor</html>"),
                _RispostaFinta(AURA_CONFIG_HTML),
                _RispostaFinta('{"event":{"descriptor":"markup://aura:invalidSession"}}'),
                # sessione riaperta
                _RispostaFinta("<html>frontdoor</html>"),
                _RispostaFinta(AURA_CONFIG_HTML),
                _risposta_aura({}),
                _risposta_aura([RIGA_D540]),
            ]
        )
        session.cookie_jar = [_CookieFinto("__Host-CSRF_TEST", "TOKEN_CSRF_TEST")]
        client = auth.AuthClient(session)
        righe = await client.async_get_misure_gse_terna(
            "ACCESS_TOKEN", "IT001E04193830", "2026-07"
        )
        assert righe == [RIGA_D540]

    async def test_azione_fallita_solleva_parsing_error(self):
        session = _SessioneACoda(
            [
                _RispostaFinta("<html>frontdoor</html>"),
                _RispostaFinta(AURA_CONFIG_HTML),
                _RispostaFinta(
                    json.dumps({"actions": [{"id": "1;a", "state": "ERROR"}]})
                ),
            ]
        )
        session.cookie_jar = [_CookieFinto("__Host-CSRF_TEST", "T")]
        client = auth.AuthClient(session)
        with pytest.raises(auth.ParsingError):
            await client.async_get_misure_gse_terna(
                "ACCESS_TOKEN", "IT001E04193830", "2026-07"
            )
