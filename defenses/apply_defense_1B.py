#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apply_defense_1B.py  -  Defensa 1B (gate de plausibilidad de telemetria de bateria)

Aplica, de forma idempotente, el gate de plausibilidad sobre BATT_VOLTAGE en el
FSW del componente GENERIC_EPS, para mitigar el vector 1B (telemetria de bateria
falsa -> suspension persistente de ciencia / DoS).

Mecanismo:
  - Slew-rate: una caida de BATT_VOLTAGE mayor que un limite fisico por muestra
    es implausible (una bateria no pierde ~1 V en segundos).
  - Cross-check solar: la caida brusca solo se considera sospechosa si NO esta
    corroborada por una caida del panel solar (SolarArrayVoltage).
  - Al detectar sospecha: se RETIENE el ultimo valor valido (se sanea en el sitio,
    offset 20, para que el watchpoint LC #27 no dispare), se incrementa un contador
    y se emite un evento cFS (evidencia en consola).

NO cambia el offset de BatteryVoltage (sigue en 20) ni la definicion de telemetria
de COSMOS. Dos archivos editados, ambos en el submodulo components/generic_eps.

Uso:
    cd ~/nos3
    python3 apply_defense_1B.py
    # revisar el resumen; luego:
    make config && make fsw && make launch
"""

import os
import sys

# Raiz del repo: asume ejecucion desde ~/nos3 (o ajustar NOS3_ROOT)
ROOT = os.environ.get("NOS3_ROOT", os.getcwd())

EPS = os.path.join(ROOT, "components", "generic_eps", "fsw", "cfs", "src")
EVENTS_H = os.path.join(EPS, "generic_eps_events.h")
APP_C = os.path.join(EPS, "generic_eps_app.c")

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def ok(msg):
    print(f"{GREEN}[OK]{RESET}   {msg}")


def ya(msg):
    print(f"{YELLOW}[YA]{RESET}   {msg}")


def err(msg):
    print(f"{RED}[ERROR]{RESET} {msg}")


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------------------
# Edicion 1: nuevo event ID en generic_eps_events.h
# ---------------------------------------------------------------------------
def edit_events():
    if not os.path.isfile(EVENTS_H):
        err(f"No existe {EVENTS_H}")
        return False
    src = read(EVENTS_H)
    if "GENERIC_EPS_BATT_SPOOF_ERR_EID" in src:
        ya("events.h: GENERIC_EPS_BATT_SPOOF_ERR_EID ya definido")
        return True
    anchor = "#define GENERIC_EPS_REQ_HK_ERR_EID     31"
    if anchor not in src:
        err("events.h: no encuentro el ancla (GENERIC_EPS_REQ_HK_ERR_EID 31)")
        return False
    add = anchor + "\n#define GENERIC_EPS_BATT_SPOOF_ERR_EID  32"
    write(EVENTS_H, src.replace(anchor, add, 1))
    ok("events.h: agregado GENERIC_EPS_BATT_SPOOF_ERR_EID = 32")
    return True


# ---------------------------------------------------------------------------
# Edicion 2a: #define del limite de slew (file scope, antes de ReportHousekeeping)
# ---------------------------------------------------------------------------
DEFINE_BLOCK = """/*
** Defensa 1B: limite fisico de cambio de BATT_VOLTAGE por muestra (mV).
** Una caida mayor es implausible para una bateria real y se trata como sospechosa.
** Valor de referencia; el control operacional completo usa telemetria autenticada.
*/
#define GENERIC_EPS_BATT_MAX_SLEW_MV 800

/*
** Report Application Housekeeping
*/
void GENERIC_EPS_ReportHousekeeping(void)"""

DEFINE_ANCHOR = """/*
** Report Application Housekeeping
*/
void GENERIC_EPS_ReportHousekeeping(void)"""


def edit_app_define():
    src = read(APP_C)
    if "GENERIC_EPS_BATT_MAX_SLEW_MV" in src:
        ya("app.c: #define GENERIC_EPS_BATT_MAX_SLEW_MV ya presente")
        return True, src
    if DEFINE_ANCHOR not in src:
        err("app.c: no encuentro el ancla de ReportHousekeeping (para el #define)")
        return False, src
    src = src.replace(DEFINE_ANCHOR, DEFINE_BLOCK, 1)
    write(APP_C, src)
    ok("app.c: agregado #define GENERIC_EPS_BATT_MAX_SLEW_MV 800")
    return True, src


# ---------------------------------------------------------------------------
# Edicion 2b: bloque de validacion dentro de ReportHousekeeping (antes del publish)
# ---------------------------------------------------------------------------
VALID_ANCHOR = """    /* Time stamp and publish housekeeping telemetry */
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&GENERIC_EPS_AppData.HkTelemetryPkt);"""

VALID_BLOCK = """    /*
    ** Defensa 1B: gate de plausibilidad sobre BATT_VOLTAGE antes de publicar el HK.
    ** El FDIR (watchpoint LC #27) suspende la ciencia si BATT_VOLTAGE < umbral. Una
    ** lectura falsificada o un sensor atascado puede forzar una suspension persistente
    ** (DoS). Se rechaza una caida fisicamente implausible (slew) de la bateria que NO
    ** este corroborada por una caida del panel solar, reteniendo el ultimo valor valido.
    ** Control de resiliencia/deteccion, no de autenticacion (ver caveat del paper).
    */
    {
        static uint8  GENERIC_EPS_BattSeeded    = 0;
        static uint16 GENERIC_EPS_LastValidBatt = 0;
        static uint16 GENERIC_EPS_LastSolar     = 0;
        static uint32 GENERIC_EPS_BattSuspect   = 0;

        uint16 batt  = GENERIC_EPS_AppData.HkTelemetryPkt.DeviceHK.BatteryVoltage;
        uint16 solar = GENERIC_EPS_AppData.HkTelemetryPkt.DeviceHK.SolarArrayVoltage;

        if (GENERIC_EPS_BattSeeded == 0)
        {
            GENERIC_EPS_LastValidBatt = batt;
            GENERIC_EPS_LastSolar     = solar;
            GENERIC_EPS_BattSeeded    = 1;
        }
        else
        {
            uint16 batt_drop  = (batt  < GENERIC_EPS_LastValidBatt) ? (GENERIC_EPS_LastValidBatt - batt) : 0;
            uint16 solar_drop = (solar < GENERIC_EPS_LastSolar)     ? (GENERIC_EPS_LastSolar - solar)     : 0;

            if ((batt_drop > GENERIC_EPS_BATT_MAX_SLEW_MV) &&
                (solar_drop < (GENERIC_EPS_BATT_MAX_SLEW_MV / 2)))
            {
                /* Caida brusca de bateria NO corroborada por el panel solar: sospechosa. */
                GENERIC_EPS_BattSuspect++;
                CFE_EVS_SendEvent(GENERIC_EPS_BATT_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                    "EPS: BATT_VOLTAGE sospechoso, caida %u>%u mV sin corroborar; retiene %u mV [susp=%u]",
                    (unsigned int)batt_drop, (unsigned int)GENERIC_EPS_BATT_MAX_SLEW_MV,
                    (unsigned int)GENERIC_EPS_LastValidBatt, (unsigned int)GENERIC_EPS_BattSuspect);
                /* Sanea en el sitio: el watchpoint LC (offset 20) ve el ultimo valor valido. */
                GENERIC_EPS_AppData.HkTelemetryPkt.DeviceHK.BatteryVoltage = GENERIC_EPS_LastValidBatt;
            }
            else
            {
                /* Lectura plausible (o corroborada por el solar): se acepta y actualiza baseline. */
                GENERIC_EPS_LastValidBatt = batt;
            }
            GENERIC_EPS_LastSolar = solar;
        }
    }

"""


def edit_app_block(src):
    if "Defensa 1B: gate de plausibilidad" in src:
        ya("app.c: bloque de validacion 1B ya presente")
        return True
    if VALID_ANCHOR not in src:
        err("app.c: no encuentro el ancla del publish (CFE_SB_TimeStampMsg)")
        return False
    src = src.replace(VALID_ANCHOR, VALID_BLOCK + VALID_ANCHOR, 1)
    write(APP_C, src)
    ok("app.c: insertado el gate de plausibilidad en GENERIC_EPS_ReportHousekeeping")
    return True


def main():
    print(f"Raiz NOS3: {ROOT}")
    if not os.path.isfile(APP_C):
        err(f"No existe {APP_C}")
        err("Ejecuta desde ~/nos3 (o exporta NOS3_ROOT). El submodulo generic_eps debe estar poblado.")
        sys.exit(1)

    results = []
    results.append(edit_events())
    done_def, src = edit_app_define()
    results.append(done_def)
    if done_def:
        # releer para asegurar el bloque mas reciente
        src = read(APP_C)
        results.append(edit_app_block(src))
    else:
        results.append(False)

    print()
    if all(results):
        ok("Defensa 1B aplicada. Siguiente: cd ~/nos3 && make config && make fsw && make launch")
    else:
        err("Alguna edicion fallo; revisa los mensajes de arriba. No se continuo el build.")
        sys.exit(1)


if __name__ == "__main__":
    main()
