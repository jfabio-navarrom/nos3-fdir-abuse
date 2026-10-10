#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fase 4 - Defensa 1A: gate de autorizacion del cambio de modo (CM0044) en NOS3/MGR.
Aplica los 4 cambios por ruta de archivo. Idempotente: si ya estan aplicados, lo dice.
Uso:  python3 apply_defense_1A.py
"""
import os, sys

HOME = os.path.expanduser("~")
BASE = os.path.join(HOME, "nos3")

MGR_SRC = os.path.join(BASE, "components/mgr/fsw/cfs/src")
MSG_H   = os.path.join(MGR_SRC, "mgr_msg.h")
APP_C   = os.path.join(MGR_SRC, "mgr_app.c")
RTS025  = os.path.join(BASE, "cfg/nos3_defs/tables/sc_rts025.c")
CMD_TXT = os.path.join(BASE, "components/mgr/gsw/MGR/cmd_tlm/MGR_CMD.txt")

GREEN = "\033[92m"; RED = "\033[91m"; YEL = "\033[93m"; RST = "\033[0m"
ok = lambda m: print(GREEN + "  OK   " + RST + m)
skip = lambda m: print(YEL + " YA    " + RST + m)
err = lambda m: print(RED + " ERROR " + RST + m)

errors = 0

def patch(path, replacements, sentinel):
    """replacements: lista de (old, new). sentinel: texto que indica 'ya aplicado'."""
    global errors
    rel = path.replace(HOME, "~")
    if not os.path.isfile(path):
        err("no existe: " + rel); errors += 1; return
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    if sentinel in txt:
        skip(rel + "  (ya estaba aplicado)"); return
    new = txt
    for old, rep in replacements:
        if old not in new:
            err(rel + "  -> no encontre el ancla esperada (no toco el archivo)")
            errors += 1; return
        new = new.replace(old, rep, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    ok(rel)

# --- Archivo 1: mgr_msg.h -------------------------------------------------
MSG_OLD = "    uint8                   U8;\n\n} MGR_U8_cmd_t;"
MSG_NEW = MSG_OLD + """

/*
** Token de autorizacion para el cambio de modo (gate cyber-safe mode, CM0044).
** Implementacion de referencia: token estatico de 1 byte. El valor 0xA5 es
** endianness-invariante y mantiene la demo simple. La version real usa un MAC
** por comando sobre un enlace autenticado (CCSDS SDLS).
*/
#define MGR_MODE_AUTH_TOKEN 0xA5

/*
** Set mode command con token de autorizacion.
** Igual que MGR_U8_cmd_t pero con un byte extra: el token.
*/
typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint8                   U8;        /* modo deseado (SAFE/SCIENCE/...) */
    uint8                   AuthToken; /* token de autorizacion */

} MGR_SetModeAuth_cmd_t;"""
patch(MSG_H, [(MSG_OLD, MSG_NEW)], sentinel="MGR_SetModeAuth_cmd_t")

# --- Archivo 2: mgr_app.c (bloque case MGR_SET_MODE_CC) -------------------
APP_OLD = """        case MGR_SET_MODE_CC:
            if (MGR_VerifyCmdLength(MGR_AppData.MsgPtr, sizeof(MGR_U8_cmd_t)) == OS_SUCCESS)
            {
                MGR_U8_cmd_t *mode_cmd = (MGR_U8_cmd_t *)MGR_AppData.MsgPtr;
                if ((mode_cmd->U8 < MGR_SAFE_MODE) || (mode_cmd->U8 > MGR_SCIENCE_REBOOT_MODE))
                {
                    CFE_EVS_SendEvent(MGR_CMD_SETMODE_ERR_EID, CFE_EVS_EventType_ERROR,
                                      "MGR: Invalid mode commanded [%d], mode remains [%d]", mode_cmd->U8,
                                      MGR_AppData.HkTelemetryPkt.SpacecraftMode);
                }
                else
                {
                    MGR_AppData.HkTelemetryPkt.SpacecraftMode = mode_cmd->U8;
                    CFE_EVS_SendEvent(MGR_CMD_SETMODE_INF_EID, CFE_EVS_EventType_INFORMATION,
                                      "MGR: Set mode command received [%d]", MGR_AppData.HkTelemetryPkt.SpacecraftMode);
                }
            }
            break;"""
APP_NEW = """        case MGR_SET_MODE_CC:
            if (MGR_VerifyCmdLength(MGR_AppData.MsgPtr, sizeof(MGR_SetModeAuth_cmd_t)) == OS_SUCCESS)
            {
                MGR_SetModeAuth_cmd_t *mode_cmd = (MGR_SetModeAuth_cmd_t *)MGR_AppData.MsgPtr;

                /* Gate de autorizacion (CM0044): rechazar si el token no es valido */
                if (mode_cmd->AuthToken != MGR_MODE_AUTH_TOKEN)
                {
                    MGR_AppData.HkTelemetryPkt.CommandErrorCount++;
                    CFE_EVS_SendEvent(MGR_CMD_SETMODE_ERR_EID, CFE_EVS_EventType_ERROR,
                                      "MGR: Cambio de modo NO autorizado rechazado (token [0x%02X]), modo sigue en [%d]",
                                      mode_cmd->AuthToken, MGR_AppData.HkTelemetryPkt.SpacecraftMode);
                }
                else if ((mode_cmd->U8 < MGR_SAFE_MODE) || (mode_cmd->U8 > MGR_SCIENCE_REBOOT_MODE))
                {
                    CFE_EVS_SendEvent(MGR_CMD_SETMODE_ERR_EID, CFE_EVS_EventType_ERROR,
                                      "MGR: Invalid mode commanded [%d], mode remains [%d]", mode_cmd->U8,
                                      MGR_AppData.HkTelemetryPkt.SpacecraftMode);
                }
                else
                {
                    MGR_AppData.HkTelemetryPkt.SpacecraftMode = mode_cmd->U8;
                    CFE_EVS_SendEvent(MGR_CMD_SETMODE_INF_EID, CFE_EVS_EventType_INFORMATION,
                                      "MGR: Set mode command received [%d]", MGR_AppData.HkTelemetryPkt.SpacecraftMode);
                }
            }
            break;"""
patch(APP_C, [(APP_OLD, APP_NEW)], sentinel="MGR_SetModeAuth_cmd_t *mode_cmd")

# --- Archivo 3: sc_rts025.c ----------------------------------------------
patch(
    RTS025,
    [
        ("    MGR_U8_cmd_t cmd2;", "    MGR_SetModeAuth_cmd_t cmd2;"),
        (
            "        .cmd2.U8 = MGR_SCIENCE_MODE,\n",
            "        .cmd2.U8 = MGR_SCIENCE_MODE,\n        .cmd2.AuthToken = MGR_MODE_AUTH_TOKEN,\n",
        ),
    ],
    sentinel="AuthToken = MGR_MODE_AUTH_TOKEN",
)

# --- Archivo 4: MGR_CMD.txt (editar solo dentro del bloque SET_MODE) ------
def patch_cmd_txt():
    global errors
    rel = CMD_TXT.replace(HOME, "~")
    if not os.path.isfile(CMD_TXT):
        err("no existe: " + rel); errors += 1; return
    with open(CMD_TXT, "r", encoding="utf-8") as f:
        txt = f.read()
    if "AUTH_TOKEN" in txt:
        skip(rel + "  (ya estaba aplicado)"); return
    lines = txt.split("\n")
    start = None
    for i, ln in enumerate(lines):
        if ln.startswith("COMMAND MGR MGR_SET_MODE_CC"):
            start = i; break
    if start is None:
        err(rel + "  -> no encontre el bloque MGR_SET_MODE_CC"); errors += 1; return
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("COMMAND "):
            end = j; break
    changed_len = False
    last_state = None
    for k in range(start, end):
        if ("CCSDS_LENGTH" in lines[k]) and (" 2 " in lines[k] or "MAX_UINT16 2 " in lines[k]):
            lines[k] = lines[k].replace("MAX_UINT16 2 ", "MAX_UINT16 3 ", 1)
            changed_len = True
        if lines[k].lstrip().startswith("STATE SCIENCE_REBOOT"):
            last_state = k
    if not changed_len or last_state is None:
        err(rel + "  -> estructura inesperada en el bloque SET_MODE (no toco el archivo)")
        errors += 1; return
    auth_line = '  APPEND_PARAMETER AUTH_TOKEN          8 UINT MIN_UINT8 MAX_UINT8 0         "Token de autorizacion del cambio de modo"'
    lines.insert(last_state + 1, auth_line)
    with open(CMD_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    ok(rel)

patch_cmd_txt()

print()
if errors:
    print(RED + "Hubo %d archivo(s) con problema. Mandame la salida completa y lo revisamos." % errors + RST)
    sys.exit(1)
print(GREEN + "Listo: los 4 cambios quedaron aplicados. Ahora: cd ~/nos3 && make && make launch  (SIN sudo)." + RST)
