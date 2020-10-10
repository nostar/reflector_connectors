# Reflector Connectors
Software to connect DSTAR DPlus reflectors, YSF Reflectors, and DMR talkgroups from different servers.  Example applications for these utilties are to connect a Dplus DSTAR reflector to an XLXD network via REF to REF using refcon, or connecting a Brandmeister/TGIF talkgroup to an XLXD network via dmrcon. 

# Build
Each program is a single C file, and no makefile is required.  To build, simply run gcc for each file:
```
gcc -o dmrcon dmrcon.c
gcc -o refcon refcon.c
gcc -o ysfcon ysfcon.c
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
Connect 2 DMR talkgroups
```
./dmrcon [CALLSIGN] [DMRID] [YSFHost1IP:PORT:TG] [YSFHost2IP:PORT:TG]
```

