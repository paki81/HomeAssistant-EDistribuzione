"""Export delle letture ufficiali mensili verso un webhook esterno.

Caso d'uso: le officine elettriche (impianti fotovoltaici oltre 20 kW con
autoconsumo) devono tenere il registro mensile delle letture dei contatori
per l'Agenzia delle Dogane e dei Monopoli. Le letture ufficiali cumulative
di E-Distribuzione (endpoint /reading) vengono inviate a un webhook -
tipicamente n8n self-hosted - che le mappa su un foglio Google
preformattato con le formule del registro.

Il payload contiene sia la risposta grezza ('letture') sia una vista
piatta ('righe': una riga per ogni slot pubblicato, con i campi della
lettura ripetuti), pensata per nodi tipo 'Split Out' di n8n.
"""
from __future__ import annotations

import logging
from datetime import date, timedelta

import aiohttp

from .const import TIPO_POD_DEFAULT

_LOGGER = logging.getLogger(__name__)

TIPO_EVENTO = "lettura_mensile_edistribuzione"

# Tempo massimo della chiamata al webhook: un endpoint lento non deve
# trattenere il ciclo di aggiornamento del coordinator.
_TIMEOUT_WEBHOOK = aiohttp.ClientTimeout(total=30)


class RegistroError(Exception):
    """POST al webhook fallito (errore di rete o status non-2xx)."""


def mese_precedente(oggi: date) -> tuple[int, int]:
    """(anno, mese) del mese prima di 'oggi'."""
    ultimo_precedente = oggi.replace(day=1) - timedelta(days=1)
    return ultimo_precedente.year, ultimo_precedente.month


def periodo_mese(anno: int, mese: int) -> tuple[date, date]:
    """(primo, ultimo) giorno del mese, per la richiesta /reading."""
    primo = date(anno, mese, 1)
    ultimo = date(anno, 12, 31) if mese == 12 else date(anno, mese + 1, 1) - primo.resolution
    return primo, ultimo


def finestra_lettura_fine_mese(anno: int, mese: int) -> tuple[date, date]:
    """Intervallo in cui cercare la lettura di FINE mese su /reading.

    Le letture ufficiali sono datate al 1° del mese SUCCESSIVO (verificato
    su risposta reale: measureTs "2026-09-01" con file sorgente "..._202608"
    - la lettura del 1° settembre chiude agosto). Per il mese M si cerca
    quindi la lettura misurata all'inizio di M+1, con qualche giorno di
    margine per misurazioni tardive.
    """
    primo_successivo = date(anno + 1, 1, 1) if mese == 12 else date(anno, mese + 1, 1)
    return primo_successivo, primo_successivo + timedelta(days=6)


def righe_letture(letture: list[dict]) -> list[dict]:
    """Vista piatta: una riga per ogni slot pubblicato (EA/ER per fascia da
    publishedSlots, POT da publishedPowerPeaks), con i campi della lettura
    ripetuti su ogni riga. Le chiavi degli slot (magnitude, slotId, value)
    restano quelle grezze dell'API: il connettore a valle le mappa sul
    foglio."""
    righe: list[dict] = []
    for lettura in letture:
        base = {
            k: v
            for k, v in lettura.items()
            if k not in ("publishedSlots", "publishedPowerPeaks")
        }
        for slot in (lettura.get("publishedSlots") or []) + (
            lettura.get("publishedPowerPeaks") or []
        ):
            righe.append({**base, **slot})
    return righe


def payload_registro(
    pod: str, tipo_pod: str, anno: int, mese: int, letture: list[dict]
) -> dict:
    """Payload JSON inviato al webhook per un POD e un mese."""
    primo, ultimo = periodo_mese(anno, mese)
    lettura_da, lettura_a = finestra_lettura_fine_mese(anno, mese)
    return {
        "tipo": TIPO_EVENTO,
        "pod": pod,
        "tipo_pod": tipo_pod or TIPO_POD_DEFAULT,
        "anno": anno,
        "mese": mese,
        "mese_iso": f"{anno:04d}-{mese:02d}",
        "periodo_da": primo.isoformat(),
        "periodo_a": ultimo.isoformat(),
        "lettura_fine_mese_da": lettura_da.isoformat(),
        "lettura_fine_mese_a": lettura_a.isoformat(),
        "letture": letture,
        "righe": righe_letture(letture),
    }


async def async_invia_registro(
    session: aiohttp.ClientSession, url: str, segreto: str | None, payload: dict
) -> None:
    """POST del payload al webhook. Il segreto, se configurato, va come
    'Authorization: Bearer ...' - in n8n basta l'opzione 'Header Auth' del
    nodo Webhook con lo stesso nome e valore."""
    headers = {}
    if segreto:
        headers["Authorization"] = f"Bearer {segreto}"
    try:
        async with session.post(
            url, json=payload, headers=headers, timeout=_TIMEOUT_WEBHOOK
        ) as resp:
            if resp.status >= 300:
                corpo = (await resp.text())[:300]
                raise RegistroError(
                    f"webhook {url} ha risposto {resp.status}: {corpo}"
                )
    except aiohttp.ClientError as err:
        raise RegistroError(f"webhook {url} non raggiungibile: {err}") from err
