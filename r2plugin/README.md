# r2plugin

This directory contains the make and meson files required
to link r2yara statically inside radare2 (XPS).

```console
cd radare2
mkdir -p libr/xps/p
ln -s ../../../../r2yara libr/xps/p/r2yara
cp libr/xps/p/r2yara/r2plugin/config.mk libr/xps/config.mk
make -C libr/xps
```

Then build radare2 as usual (`./configure && make` or meson).
The build requires libyara to be available via pkg-config.

Verify with:

```console
r2 -q -c 'Lc~r2yara' --
```
