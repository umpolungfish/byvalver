# Problematic Bins Directory

## Overview
This directory contains 35 .bin files that had null bytes remaining after processing with byvalver (as of commit 1d8cff3).

## Location
- **Source**: `~/RUBBISH/BIG_BIN/`
- **Problematic bins**: `~/RUBBISH/PROBLEMATIC_BINS/`

## Files (35 total)
```
2cupsnstring.bin
3peat.bin
8ball_keylogger_inject.bin
IG_coiled.bin
IG_nvenom.bin
IG_strike.bin
SolaraBootstrapper.bin
a.bin
a_1.bin
asspiss.bin
blud_thinner.bin
boofer.bin
c_B_f.bin
c_klogging.bin
calc.bin
cb_wh.bin
cert_scraper.bin
cheapsuit.bin
chompchomp.bin
compromise.bin
compromise_1.bin
compromise_2.bin
compromise_3.bin
cshost.bin
cunfyoozed_3peat.bin
cunfyoozed_rsx64.bin
cutyourmeat.bin
dapeton.bin
defender_disabler.bin
doper_c2.bin
dropper.bin
duhmento.bin
ecliptic_hookshade.bin
evasion.bin
fartbang.bin
```

## Testing Script
Use `./test_problematic_bins.py` to test only these problematic files.

This script:
- Points to `~/RUBBISH/PROBLEMATIC_BINS/` instead of `~/RUBBISH/BIG_BIN/`
- Generates results in `./test_results/problematic_bins_assessment_*.json`
- Creates summaries in `./test_results/problematic_bins_summary_*.txt`

## Usage
```bash
./test_problematic_bins.py
```

## Purpose
These files are isolated to:
1. Focus debugging efforts on specific failing patterns
2. Faster iteration (35 files vs 121 files)
3. Easier analysis of what strategies are needed
