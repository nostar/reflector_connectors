# Reflector Connectors
Software to connect DSTAR DPlus reflectors, YSF Reflectors, and DMR talkgroups from different servers.  Example applications for these utilties are to connect a Dplus DSTAR reflector to an XLXD network via REF to REF using refcon, or connecting a Brandmeister/TGIF talkgroup to an XLXD network via dmrcon. 

# Build

```bash
make all          # build every connector
make dgidcon      # one target: dmrcon | refcon | ysfcon | dgidcon | xrfcon
make clean
```

Or compile by hand:
```
gcc -o dmrcon dmrcon.c
gcc -o refcon refcon.c
gcc -o ysfcon ysfcon.c
gcc -o dgidcon dgidcon.c
gcc -o xrfcon xrfcon.c
```

# Usage
Connect 2 DSTAR DPlus (REF) reflectors:
```
./refcon [CALLSIGN] [REFName:Module:REFHostname:Port] [REFName:Module:REFHostname:Port]
```
Connect 2 YSF reflectors
```
./ysfcon [CALLSIGN] [YSFHost1IP:PORT] [YSFHost2IP:PORT]
```
Connect 2 YSF reflectors fix DG-ID
```
./dgidcon [CALLSIGN] [YSFHost1IP:PORT] [YSFHost2IP:PORT] [DG-ID_YSF1] [DG-ID_YSF2]
```
Connect 2 DMR talkgroups
```
./dmrcon [CALLSIGN] [DMRID] [DMRHost1IP:PORT:TG:PW] [DMRHost2IP:PORT:TG:PW]
```

