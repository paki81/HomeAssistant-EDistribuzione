"""Test per registro.py e per l'export mensile del coordinator.

registro.py è un modulo puro (solo aiohttp + const): caricato via importlib
come test_api.py/test_auth.py. I test del coordinator usano il fixture
make_edist_coordinator con api e invio webhook simulati.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from datetime import date
from pathlib import Path
from unittest.mock import AsyncMock

import aiohttp
import pytest
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

PKG_DIR = Path(__file__).parent.parent / "custom_components" / "edistribuzione"


def _load_registro_module():
    pkg_name = "edistribuzione_test_registro"
    if f"{pkg_name}.registro" in sys.modules:
        return sys.modules[f"{pkg_name}.registro"]

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
    return _load("registro", "registro.py")


registro = _load_registro_module()

from custom_components.edistribuzione.const import (  # noqa: E402
    CONF_REGISTRO_SEGRETO,
    CONF_REGISTRO_WEBHOOK,
    CONF_STATO_REGISTRO,
)

# RegistroError DEVE venire dal package reale: la copia caricata via
# importlib qui sopra è una classe distinta e non sarebbe catturata dal
# coordinator (che importa da custom_components.edistribuzione.registro).
from custom_components.edistribuzione.registro import RegistroError  # noqa: E402

from .conftest import POD_A, POD_B  # noqa: E402

# Struttura fedele a una risposta reale dell'endpoint /reading.
LETTURA = {
    "pod": POD_A,
    "meterSerialNumber": "23E4E5KE104572837",
    "measureTs": "2026-10-01T00:00:00+02:00",
    "publishedSlots": [
        {"magnitude": "EA", "slotId": "T1", "value": 1000.5},
        {"magnitude": "EA", "slotId": "T2", "value": 2000.25},
        {"magnitude": "ER", "slotId": "T1", "value": None},
    ],
    "publishedPowerPeaks": [
        {"magnitude": "POT", "slotId": "T1", "value": 4.2},
        {"magnitude": "POT", "slotId": "T2", "value": None},
    ],
}


# ---------------------------------------------------------------------------
# registro.py puro
# ---------------------------------------------------------------------------


class TestDateHelper:
    def test_mese_precedente_normale(self):
        assert registro.mese_precedente(date(2026, 10, 15)) == (2026, 9)

    def test_mese_precedente_a_cavallo_dell_anno(self):
        assert registro.mese_precedente(date(2027, 1, 1)) == (2026, 12)

    def test_periodo_mese(self):
        assert registro.periodo_mese(2026, 9) == (date(2026, 9, 1), date(2026, 9, 30))
        # Febbraio di un anno bisestile: il mese ha il suo ultimo giorno vero.
        assert registro.periodo_mese(2028, 2) == (date(2028, 2, 1), date(2028, 2, 29))
        assert registro.periodo_mese(2026, 12) == (date(2026, 12, 1), date(2026, 12, 31))

    def test_finestra_lettura_fine_mese(self):
        """La lettura di fine settembre è datata al confine del mese
        (misurata il 1° ottobre o il 30 settembre): la finestra copre
        dall'ultimo del mese a metà del mese successivo, perché contatori
        diversi pubblicano con tempi diversi."""
        assert registro.finestra_lettura_fine_mese(2026, 9) == (
            date(2026, 9, 30),
            date(2026, 10, 15),
        )
        assert registro.finestra_lettura_fine_mese(2026, 12) == (
            date(2026, 12, 31),
            date(2027, 1, 15),
        )


class TestRigheLetture:
    def test_una_riga_per_slot_e_picco_con_campi_della_lettura(self):
        righe = registro.righe_letture([LETTURA])
        # 3 publishedSlots + 2 publishedPowerPeaks
        assert len(righe) == 5
        assert righe[0] == {
            "pod": POD_A,
            "meterSerialNumber": "23E4E5KE104572837",
            "measureTs": "2026-10-01T00:00:00+02:00",
            "magnitude": "EA",
            "slotId": "T1",
            "value": 1000.5,
        }
        # value: null resta None, non sparisce né diventa 0.
        assert righe[2]["value"] is None and righe[2]["magnitude"] == "ER"
        # Anche i picchi di potenza finiscono in righe, con magnitude POT.
        assert righe[3]["magnitude"] == "POT" and righe[3]["value"] == 4.2
        assert "publishedSlots" not in righe[0] and "publishedPowerPeaks" not in righe[0]

    def test_lettura_senza_slot_non_produce_righe(self):
        assert registro.righe_letture([{"POD": POD_A}]) == []
        assert registro.righe_letture([{"POD": POD_A, "publishedSlots": None}]) == []

    def test_vuota(self):
        assert registro.righe_letture([]) == []


class TestFasceMensili:
    TIME_OF_USE = [
        {
            "yearMonth": "202608",
            "readings": {
                "energyType": "A2",
                "energyT1": "454.973",
                "energyT2": "104.175",
                "energyT3": "267.223",
                "energyT4": "826.371",
            },
        },
        {
            "yearMonth": "202609",
            "readings": {
                "energyType": "A2",
                "energyT1": "354.499",
                "energyT2": "106.749",
                "energyT3": "72.474",
                "energyT4": "533.722",
            },
        },
    ]

    def test_estrae_il_mese_giusto_da_risposta_multi_mese(self):
        fasce = registro.fasce_mensili(self.TIME_OF_USE, 2026, 9)
        assert fasce == {"f1": 354.499, "f2": 106.749, "f3": 72.474, "totale": 533.722}

    def test_mese_assente_ritorna_none(self):
        assert registro.fasce_mensili(self.TIME_OF_USE, 2026, 7) is None

    def test_lista_vuota_ritorna_none(self):
        assert registro.fasce_mensili([], 2026, 9) is None


class TestPayload:
    def test_struttura(self):
        payload = registro.payload_registro(POD_A, "produzione", 2026, 9, [LETTURA])
        assert payload["tipo"] == "lettura_mensile_edistribuzione"
        assert payload["pod"] == POD_A
        assert payload["tipo_pod"] == "produzione"
        assert payload["mese_iso"] == "2026-09"
        assert payload["periodo_da"] == "2026-09-01"
        assert payload["periodo_a"] == "2026-09-30"
        assert payload["letture"] == [LETTURA]
        assert payload["lettura_fine_mese_da"] == "2026-09-30"
        assert payload["lettura_fine_mese_a"] == "2026-10-15"
        assert len(payload["righe"]) == 5

    def test_misure_gse_e_fasce_opzionali(self):
        fasce = {"immessa": {"f1": 1.0, "f2": 2.0, "f3": 3.0, "totale": 6.0}}
        payload = registro.payload_registro(
            POD_A, "produzione", 2026, 9, [LETTURA], [{"fileName": "d540"}], fasce
        )
        assert payload["misure_gse_terna"] == [{"fileName": "d540"}]
        assert payload["fasce"] == fasce
        vuoto = registro.payload_registro(POD_A, "produzione", 2026, 9, [])
        assert vuoto["misure_gse_terna"] == [] and vuoto["fasce"] == {}


class _RispostaPost:
    def __init__(self, status: int, corpo: str = "ok"):
        self.status = status
        self._corpo = corpo

    async def text(self):
        return self._corpo

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _SessionePost:
    """Registra URL/json/headers dell'ultima POST; lo status è configurabile."""

    def __init__(self, status: int = 200, errore: Exception | None = None):
        self._status = status
        self._errore = errore
        self.ultima_post: dict | None = None

    def post(self, url, json=None, headers=None, timeout=None):
        self.ultima_post = {"url": url, "json": json, "headers": headers}
        if self._errore is not None:
            raise self._errore
        return _RispostaPost(self._status)


class TestInviaRegistro:
    async def test_post_con_json_e_segreto(self):
        sessione = _SessionePost()
        payload = {"tipo": "x"}
        await registro.async_invia_registro(
            sessione, "http://n8n.local/webhook/abc", "segretone", payload
        )
        assert sessione.ultima_post["url"] == "http://n8n.local/webhook/abc"
        assert sessione.ultima_post["json"] == payload
        assert sessione.ultima_post["headers"] == {"Authorization": "Bearer segretone"}

    async def test_senza_segreto_nessun_header(self):
        sessione = _SessionePost()
        await registro.async_invia_registro(sessione, "http://n8n/", None, {})
        assert sessione.ultima_post["headers"] == {}

    async def test_status_errore_sollevato(self):
        with pytest.raises(registro.RegistroError, match="500"):
            await registro.async_invia_registro(_SessionePost(500), "http://x/", None, {})

    async def test_errore_di_rete_sollevato(self):
        sessione = _SessionePost(errore=aiohttp.ClientConnectionError("giù"))
        with pytest.raises(registro.RegistroError, match="non raggiungibile"):
            await registro.async_invia_registro(sessione, "http://x/", None, {})


# ---------------------------------------------------------------------------
# Export automatico nel coordinator
# ---------------------------------------------------------------------------


def _coordinator_con_webhook(
    make_edist_coordinator, letture, pods=None, **options_extra
):
    """Coordinator con webhook configurato e letture API simulate."""
    coordinator = make_edist_coordinator(
        pods=pods,
        options={
            CONF_REGISTRO_WEBHOOK: "http://n8n.local/webhook/abc",
            **options_extra,
        },
    )
    coordinator._api.async_get_reading = AsyncMock(return_value=letture)
    # Dati accessori dell'export: simulati perché toccherebbero la rete.
    coordinator._api.async_get_monthly_time_of_use = AsyncMock(return_value=[])
    coordinator._auth.async_get_misure_gse_terna = AsyncMock(return_value=[])
    return coordinator


def _patch_invio(monkeypatch):
    """Sostituisce l'invio HTTP con un mock; ritorna l'AsyncMock."""
    invio = AsyncMock()
    monkeypatch.setattr(
        "custom_components.edistribuzione.coordinator.async_invia_registro", invio
    )
    return invio


class TestExportAutomatico:
    async def test_senza_webhook_niente_richieste(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        coordinator = make_edist_coordinator()
        coordinator._api.async_get_reading = AsyncMock()
        invio = _patch_invio(monkeypatch)

        await coordinator._async_esporta_registro()

        coordinator._api.async_get_reading.assert_not_awaited()
        invio.assert_not_awaited()

    async def test_letture_del_mese_precedente_inviate_e_segnate(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        coordinator = _coordinator_con_webhook(make_edist_coordinator, [LETTURA])
        invio = _patch_invio(monkeypatch)

        await coordinator._async_esporta_registro()

        invio.assert_awaited_once()
        url, segreto, payload = invio.await_args.args[1:]
        assert url == "http://n8n.local/webhook/abc"
        assert segreto is None
        assert payload["pod"] == POD_A
        # La richiesta API copre la finestra nel mese SUCCESSIVO: la lettura
        # di fine mese è datata al 1° del mese dopo.
        anno, mese = registro.mese_precedente(date.today())
        da_atteso, a_atteso = registro.finestra_lettura_fine_mese(anno, mese)
        assert coordinator._api.async_get_reading.await_args.args == (
            POD_A,
            da_atteso,
            a_atteso,
        )
        anno, mese = registro.mese_precedente(date.today())
        assert payload["mese_iso"] == f"{anno:04d}-{mese:02d}"
        assert payload["letture"] == [LETTURA]
        # Il mese risulta esportato: un secondo giro non reinvia.
        assert coordinator.entry.data[CONF_STATO_REGISTRO][POD_A]["esportato"] == payload[
            "mese_iso"
        ]
        await coordinator._async_esporta_registro()
        invio.assert_awaited_once()

    async def test_segreto_delle_opzioni_passato_all_invio(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        coordinator = _coordinator_con_webhook(
            make_edist_coordinator, [LETTURA], **{CONF_REGISTRO_SEGRETO: "s3cr3t"}
        )
        invio = _patch_invio(monkeypatch)
        await coordinator._async_esporta_registro()
        assert invio.await_args.args[2] == "s3cr3t"

    async def test_letture_non_pubblicate_ritenta_una_volta_al_giorno(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        coordinator = _coordinator_con_webhook(make_edist_coordinator, [])
        invio = _patch_invio(monkeypatch)

        await coordinator._async_esporta_registro()
        assert coordinator._api.async_get_reading.await_count == 1
        assert CONF_STATO_REGISTRO in coordinator.entry.data

        # Stesso giorno: il tentativo è già registrato, niente seconda richiesta.
        await coordinator._async_esporta_registro()
        assert coordinator._api.async_get_reading.await_count == 1
        invio.assert_not_awaited()

    async def test_senza_letture_ma_con_fasce_invia(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        """POD di produzione: nessuna lettura ufficiale, ma le fasce
        mensili bastano per l'export."""
        anno, mese = registro.mese_precedente(date.today())
        coordinator = _coordinator_con_webhook(make_edist_coordinator, [])
        coordinator._api.async_get_monthly_time_of_use = AsyncMock(
            return_value=[
                {
                    "readings": {
                        "energyType": "A2",
                        "energyT1": "10.0",
                        "energyT2": "20.0",
                        "energyT3": "30.0",
                        "energyT4": "60.0",
                    },
                    "yearMonth": f"{anno:04d}{mese:02d}",
                }
            ]
        )
        invio = _patch_invio(monkeypatch)

        await coordinator._async_esporta_registro()

        invio.assert_awaited_once()
        payload = invio.await_args.args[3]
        assert payload["letture"] == []
        assert payload["fasce"]["immessa"] == {
            "f1": 10.0,
            "f2": 20.0,
            "f3": 30.0,
            "totale": 60.0,
        }

    async def test_errore_api_ritenta_domani_senza_morire(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        from custom_components.edistribuzione.api import ApiError

        coordinator = _coordinator_con_webhook(make_edist_coordinator, [])
        coordinator._api.async_get_reading = AsyncMock(side_effect=ApiError("giù"))
        invio = _patch_invio(monkeypatch)

        await coordinator._async_esporta_registro()  # non solleva
        invio.assert_not_awaited()
        assert coordinator.entry.data[CONF_STATO_REGISTRO][POD_A]["tentativo"]

    async def test_errore_webhook_ritenta_domani_senza_morire(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        coordinator = _coordinator_con_webhook(make_edist_coordinator, [LETTURA])
        invio = _patch_invio(monkeypatch)
        invio.side_effect = RegistroError("webhook 500")

        await coordinator._async_esporta_registro()  # non solleva
        stato = coordinator.entry.data[CONF_STATO_REGISTRO][POD_A]
        assert "esportato" not in stato and stato["tentativo"]

    async def test_ogni_pod_ha_il_suo_export(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        coordinator = _coordinator_con_webhook(
            make_edist_coordinator, [LETTURA], pods=[POD_A, POD_B]
        )
        invio = _patch_invio(monkeypatch)

        await coordinator._async_esporta_registro()

        assert invio.await_count == 2
        pods_inviati = {c.args[3]["pod"] for c in invio.await_args_list}
        assert pods_inviati == {POD_A, POD_B}


class TestExportManuale:
    async def test_webhook_mancante_errore_tradotto(self, hass, make_edist_coordinator):
        coordinator = make_edist_coordinator()
        with pytest.raises(ServiceValidationError) as err:
            await coordinator.async_esporta_registro("2026-09")
        assert err.value.translation_key == "registro_webhook_non_configurato"

    async def test_mese_malformato(self, hass, make_edist_coordinator):
        coordinator = _coordinator_con_webhook(make_edist_coordinator, [])
        for mese in ("settembre", "2026/09", "2026-13", "2026-1"):
            with pytest.raises(ServiceValidationError) as err:
                await coordinator.async_esporta_registro(mese)
            assert err.value.translation_key == "mese_non_valido"

    async def test_pod_non_configurato(self, hass, make_edist_coordinator):
        coordinator = _coordinator_con_webhook(make_edist_coordinator, [])
        with pytest.raises(ServiceValidationError) as err:
            await coordinator.async_esporta_registro("2026-09", pod="IT001E99999999")
        assert err.value.translation_key == "pod_non_configurato"

    async def test_export_riuscito_aggiorna_lo_stato(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        coordinator = _coordinator_con_webhook(make_edist_coordinator, [LETTURA])
        invio = _patch_invio(monkeypatch)
        coordinator._async_ensure_token = AsyncMock()

        await coordinator.async_esporta_registro("2026-09")

        invio.assert_awaited_once()
        payload = invio.await_args.args[3]
        assert payload["mese_iso"] == "2026-09"
        assert coordinator.entry.data[CONF_STATO_REGISTRO][POD_A]["esportato"] == "2026-09"

    async def test_nessuna_lettura_e_errore_visibile(
        self, hass, make_edist_coordinator, monkeypatch
    ):
        coordinator = _coordinator_con_webhook(make_edist_coordinator, [])
        _patch_invio(monkeypatch)
        coordinator._async_ensure_token = AsyncMock()

        with pytest.raises(HomeAssistantError) as err:
            await coordinator.async_esporta_registro("2026-09")
        assert err.value.translation_key == "export_registro_fallito"
