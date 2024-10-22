# r2yara
[![GithubCI Status](https://github.com/radareorg/r2yara/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/radareorg/r2yara/actions/workflows/ci.yml?query=branch%3Amain)

r2 and YARA, better together!

## License and Author(s)

LGPLv3 - Copyright 2014-2024 - pancake, jvoisin, jfrankowski, Sylvain Pelissier

## Installation

r2yara can be installed with `r2pm` tool running this command:

```sh
r2pm -ci r2yara
```

## Documentation

After installation, you will get the `yr` command inside `radare2` shell

```
[0x100003a84]> yr?
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
```

See `man 7 r2yara` for some examples.

### Yara generator usage

r2yara allows the creation of YARA rules directement inside radare2.

**Commands Overview**

```bash
[0x100003a84]> yrg?
Usage: yrg [action] [args..]   load and run yara rules inside r2
| yrg-          delete last pattern added to the yara rule
| yrg-*         delete all the patterns in the current rule
| yrgs ([len])  add string (optionally specify the length)
| yrgx ([len])  add hexpairs of blocksize (or custom length)
| yrgf ([len])  add function bytepattern signature
| yrgz          add all strings referenced from current function
```

To start using r2yara to create YARA rules automatically, follow these steps:

**Generate a YARA rule:**

```
[0x100003a84]> yrg
WARN: See 'yrg?' to find out which subcommands use to append patterns to the rule
rule rulename : test {
  meta:
    author = "user"
    description = "My first yara rule"
    date = "2024-10-22"
    version = "0.1"
}
```

This shows the current YARA rule.

**Add strings from the binary as patterns:**

```
[0x100003a84]> yrgs
```

**Add hex patterns:**

```
[0x100003a84]> yrgx
```

**Optionally, add function signatures:**

```
[0x100003a84]> yrgf
```

**Once you've added the desired patterns, add the currently generated yara rule:**

```
[0x100003a84]> yr+
[0x100003a84]> yrl
rulename
```

Then the rule can be used directly as any other rules.
