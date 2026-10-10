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

    Le letture ufficiali sono datate al confine del mese (verificato su
    risposta reale: measureTs "2026-10-01" con file sorgente "..._202609" -
    la lettura del 1° ottobre chiude settembre). La finestra parte
    dall'ultimo giorno del mese e copre la prima metà del mese successivo:
    contatori diversi pubblicano con tempi diversi (il contatore di scambio
    il 1°, il contatore di produzione può arrivare giorni dopo o essere
    datato all'ultimo del mese stesso). Con cadenza mensile ci si aspetta
    al massimo una lettura in questa finestra.
    """
    ultimo = (
        date(anno, 12, 31) if mese == 12 else date(anno, mese + 1, 1) - timedelta(days=1)
    )
    primo_successivo = date(anno + 1, 1, 1) if mese == 12 else date(anno, mese + 1, 1)
    return ultimo, primo_successivo + timedelta(days=14)


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


def fasce_mensili(time_of_use: list[dict], anno: int, mese: int) -> dict | None:
    """Energia mensile per fascia da una risposta querymonthlytimeofuse.

    La risposta può coprire più mesi (yearMonth 'YYYYMM'): si estrae solo la
    riga del mese richiesto. Verificato su dati reali che energyT4 è il
    totale (T1+T2+T3), non una quarta fascia: le fasce F1-F3 del registro
    corrispondono a T1-T3.
    """
    chiave = f"{anno:04d}{mese:02d}"
    for elemento in time_of_use or []:
        if elemento.get("yearMonth") != chiave:
            continue
        lett = elemento.get("readings") or {}
        try:
            return {
                "f1": float(lett["energyT1"]),
                "f2": float(lett["energyT2"]),
                "f3": float(lett["energyT3"]),
                "totale": float(lett["energyT4"]),
            }
        except (KeyError, TypeError, ValueError):
            return None
    return None


def payload_registro(
    pod: str,
    tipo_pod: str,
    anno: int,
    mese: int,
    letture: list[dict],
    misure_gse_terna: list[dict] | None = None,
    fasce: dict | None = None,
) -> dict:
    """Payload JSON inviato al webhook per un POD e un mese.

    'misure_gse_terna' sono le righe grezze della tabella 'Misure GSE-TERNA'
    del portale (categorie UPN/SSP_MIS/D540): energia prodotta, immessa e
    prelevata per fascia F1-F3 + totale, nome del file ufficiale, data di
    trasmissione e stato della misura.

    'fasce' è la vista normalizzata delle energie mensili per fascia
    (querymonthlytimeofuse A1/A2), nella forma
    {"immessa": {"f1","f2","f3","totale"}, "prelevata": {...}}.
    """
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
        "misure_gse_terna": misure_gse_terna or [],
        "fasce": fasce or {},
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
