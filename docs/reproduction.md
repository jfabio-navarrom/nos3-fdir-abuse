# Reproduction guide

This guide reproduces the two attacks and the two defenses, end to end, in NOS3.
It assumes a working NOS3 checkout at `~/nos3` with submodules populated.

## 0. Ground rules for the NOS3 build

- Run as your normal user, never as root. Do not run `make` or the NOS3 install
  with `sudo`. If a previous `sudo` left root owned files, fix it once with
  `sudo chown -R $USER:$USER ~/nos3`.
- The build flow used here is `make config`, then `make fsw`, then `make launch`.
  `make config` re-stages edited tables and sources. `make` or `make all` skips
  `make config` when the project is already configured, so after editing a stored
  command table you must run `make config` again, otherwise the old table ships.
- The ground station is COSMOS: use the Command Sender to send commands and the
  Packet Viewer to read `MGR_HK_TLM` and `GENERIC_EPS_HK_TLM`. The cFS event console
  shows the internal events.

## 1. Attack 1A: unauthenticated mode change (baseline)

1. Launch the baseline system and confirm the spacecraft is in the science mode in
   `MGR_HK_TLM`.
2. In the Command Sender, send `MGR MGR_SET_MODE_CC` with the safe reboot value.
3. Observe in `MGR_HK_TLM`: the mode changes, `CMD_COUNT` increases by one, and
   `CMD_ERR_COUNT` stays at zero. The command was accepted with no authentication.
   This is the attack. Commanding the science mode again recovers the mission, so the
   effect is reversible but repeatable.

## 2. Defense 1A: authorization gate on the mode command

The script `defenses/apply_defense_1A.py` applies four edits by path:
the authenticated command struct and token in `mgr_msg.h`, the token check in the
`MGR_SET_MODE_CC` handler in `mgr_app.c`, the token carried by RTS 025 in
`sc_rts025.c`, and the COSMOS command definition in `MGR_CMD.txt` (adds `AUTH_TOKEN`,
default 0).

```
cd ~/nos3
python3 /path/to/defenses/apply_defense_1A.py
make config && make fsw && make launch
```

Measure three cases in the Command Sender and `MGR_HK_TLM`:

| Case | Command | Expected | Signal |
|------|---------|----------|--------|
| A | mode command, `AUTH_TOKEN = 0` | rejected | `CMD_ERR_COUNT` up, mode unchanged, console prints the rejection event |
| B | mode command, `AUTH_TOKEN = 165` (0xA5) | accepted | mode changes to science |
| C | autonomous RTS 025 (carries the token) | accepted | mode returns to science after a reboot, no length error |

Case A shows the attack is blocked. Case C shows the legitimate autonomous recovery
still works. If case C fails with a length error (`Invalid msg length`), you rebuilt
the application but did not regenerate the tables: run `make config` and rebuild.

Reference evidence: `figs/fig2a_1A_console.png` (rejection event) and
`figs/fig2b_1A_mgr_hk.png` (mode stays science, error count records the rejection).

## 3. Attack 1B: forged low battery telemetry (baseline)

1. On a baseline build, confirm the science mode and a battery voltage near 25.2 V in
   `GENERIC_EPS_HK_TLM`.
2. In the NOS Terminal (the simulation command interface NOS3 opens with the system),
   select the EPS simulation node and write a lower state of charge:
   ```
   SET SIMNODE eps-command
   WRITE STATE_OF_CHARGE=50
   ```
3. The reported battery voltage drops to about 24.0 V, below the low threshold.
   Watchpoint 27 becomes true, actionpoint 27 triggers RTS 27, and the science status
   changes to the low power value. Science is suspended with no command at all, and it
   stays suspended while the low reading is held. This is the persistent denial of
   service.

## 4. Defense 1B: plausibility gate on the battery telemetry

The script `defenses/apply_defense_1B.py` edits the EPS application
(`generic_eps_app.c`) and its events header. It adds a slew limit
(`GENERIC_EPS_BATT_MAX_SLEW_MV = 800`) and a gate that runs before the housekeeping
is published: if the battery voltage drops by more than the slew limit in one sample
and the solar array voltage does not drop with it, the reading is held at the last
valid value, a suspect counter is raised, and a cFS event is sent. The battery
voltage offset and the ground telemetry definition are not changed, so the existing
watchpoint benefits from the sanitized value with no table change.

```
cd ~/nos3
python3 /path/to/defenses/apply_defense_1B.py
make config && make fsw && make launch
```

Enable the science mode (which arms actionpoint 27) and run the same forged low
battery attack as in section 3.

| Scenario | Published battery voltage | Science status |
|----------|---------------------------|----------------|
| Without defense | drops to about 24.0 V | low power, science suspended |
| With defense 1B | held at about 25.2 V | initialized, science active |

The console prints a suspect event for each forged sample, with a growing counter.
A sustained attack is rejected the same way at each sample, because each reading is
compared against the held valid value.

Reference evidence: `figs/fig3a_1B_console.png` (suspect cascade),
`figs/fig3b_1B_eps.png` (battery held at 25.199 V), and `figs/fig3c_1B_mgr.png`
(science stays initialized).

## Notes

- The two defense scripts are idempotent. Running them twice reports that the change
  is already applied and does not duplicate it.
- The token in defense 1A is a single static byte, a reference implementation of the
  authorization gate, not cryptography. An operational version uses an authenticated
  command link (CCSDS SDLS with a message authentication code per command).
- Defense 1B is a resilience and detection control, not authentication. It stops an
  instantaneous spoof and raises an alert. An attacker who lowers the value slowly,
  inside the slew limit, could still move the reading down over time.
