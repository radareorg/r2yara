# r2yara
[![GithubCI Status](https://github.com/radareorg/r2yara/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/radareorg/r2yara/actions/workflows/ci.yml?query=branch%3Amain)

r2 and yara, better together!

## License and Author(s)

LGPLv3 - Copyright 2014-2024 - pancake, jvoisin, jfrankowski, Sylvain Pelissier

## Installation

After running this command:

```sh
r2pm -ci r2yara
```

## Documentation

See `man 7 r2yara` for some examples.

You will get the `yr` command inside `radare2` shell

```
[0x100003a84]> yr?*
Usage: yr [action] [args..]   load and run yara rules inside r2
| yr [file]        add yara rules from file
| yr               same as yr?
| yr-*             unload all the rules
| yr?              show this help (same as 'yara?')
| yrg[?][-sx]      generate yara rule
| yrl              list loaded rules
| yrs[q]           scan the current file, suffix with 'q' for quiet mode
| yrt ([tagname])  list tags from loaded rules, or list rules from given tag
| yrv              show version information about r2yara and yara
Usage: yrg [action] [args..]   load and run yara rules inside r2
| yrg-          delete last pattern added to the yara rule
| yrg-*         delete all the patterns in the current rule
| yrgs ([len])  add string (optionally specify the length)
| yrgx ([len])  add hexpairs of blocksize (or custom length)
| yrgf ([len])  add function bytepattern signature
| yrgz          add all strings referenced from current function
[0x100003a84]>
```

Run it like this:

```
$ radare2 /bin/ls
> yr hello.yara   # load this rule
> yrs             # scan for all the loaded rules
HelloWorld
0x000045f9: yara0.HelloWorld_0 : 6c6962
0x00004685: yara0.HelloWorld_1 : 6c6962
```
