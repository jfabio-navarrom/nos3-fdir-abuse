# Abuse of Autonomous FDIR and Safe Mode in Small Satellites

Reproducible research artifact for two attacks on the autonomous fault management
(FDIR) and safe mode logic of a representative open source flight software stack,
and one measured defense for each attack. Everything runs in simulation, on the
NASA Operational Simulator for Small Satellites (NOS3) with the core Flight System
(cFS) and the COSMOS ground station.

Author: Jose Fabio Navarro Mora (Independent Researcher).

## Scope and ethics

This work is defensive and academic. All testing is done inside the NOS3 simulator
on open source NASA software. No real satellite and no real ground system is
involved. The two attacks rely on design properties of the reference configuration
(a mode command accepted without authentication, and an FDIR branch that acts on a
single telemetry field). These properties are public and visible in the open source
code and tables, they are not a secret vulnerability.

If a specific vulnerability in the open source code is identified during this work,
rather than a public design property, it is reported to the maintainers through
their stated channels before any public description, following responsible
disclosure.

## What is here

```
nos3-fdir-abuse/
  README.md                 this file
  docs/
    reproduction.md         step by step reproduction of both attacks and both defenses
  defenses/
    apply_defense_1A.py     authorization gate on the mode command (SPARTA CM0044)
    apply_defense_1B.py     plausibility gate on the battery telemetry
  figs/                     reference evidence screenshots from our runs
  paper/                    the write up (LaTeX) once added
```

## The two attacks

- **Vector 1A, unauthenticated mode change.** The manager command `MGR_SET_MODE_CC`
  is accepted after only a length and range check, with no authentication. A single
  command moves the spacecraft out of the science mode. Reversible but repeatable.
- **Vector 1B, forged low battery telemetry.** The low power branch of the FDIR
  suspends science when the battery voltage field drops below a threshold. A forged
  low reading triggers this with no command at all, and because recovery needs a
  well charged reading, the science stays suspended while the false value is held.
  This is a persistent denial of service.

## The two defenses

- **Defense 1A (`defenses/apply_defense_1A.py`).** Adds an authorization token to
  the mode command and changes the manager handler to apply the mode change only
  when the token is valid. The autonomous recovery sequence RTS 025 is updated to
  carry the token, so the legitimate internal use keeps working. Reference
  implementation of the gate, not cryptography.
- **Defense 1B (`defenses/apply_defense_1B.py`).** Adds a plausibility gate to the
  battery telemetry inside the EPS application, before the housekeeping is published.
  A drop larger than a physical slew limit in one sample, not corroborated by a drop
  of the solar array voltage, is marked as suspect. The gate holds the last valid
  value, raises a counter, and sends a cFS event. Resilience and detection control,
  not authentication.

Both scripts are idempotent. They edit files by path under `~/nos3` and report if a
change is already applied.

## Requirements

- A working NOS3 checkout at `~/nos3` (submodules populated), able to build and run.
- Python 3 for the defense scripts.

Reproduction steps, including the exact build flow and the common pitfalls, are in
[docs/reproduction.md](docs/reproduction.md).

## How to cite

J. Navarro Mora. "Abuse of Autonomous FDIR and Safe Mode in Small Satellites:
Attack Vectors and Simulated Defenses." (preprint, 2026).

## License

J. Navarro Mora. “Abuse of Autonomous FDIR and Safe Mode in Small Satellites: Attack Vectors and Simulated Defenses.” Zenodo, 2026. DOI: 10.5281/zenodo.23287897
