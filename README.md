# reflector_connectors
Software to connect DSTAR DPlus reflectors, YSF Reflectors, and DMR talkgroups from different servers

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
./refcon [CALLSIGN] [REFName]:[Module]:[REFHostname][Port] [REFName]:[Module]:[REFHostname][Port]
```
Connect 2 YSF reflectors
```
./ysfcon [CALLSIGN] [YSFHost1IP:PORT] [YSFHost2IP:PORT]
```
Connect 2 DMR talkgroups (example, connect a Brandmeister talkgroup to an XLXD server)
```
./dmrcon [CALLSIGN] [DMRID] [YSFHost1IP:PORT:TG] [YSFHost2IP:PORT:TG]
```

