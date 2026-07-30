savedcmd_vac.ko := ld -r -m elf_x86_64 -z noexecstack --no-warn-rwx-segments --build-id=sha1  -T /usr/lib/modules/6.18.40-3-lts/build/scripts/module.lds -o vac.ko vac.o vac.mod.o .module-common.o
