savedcmd_vac.mod := printf '%s\n'   vac.o | awk '!x[$$0]++ { print("./"$$0) }' > vac.mod
