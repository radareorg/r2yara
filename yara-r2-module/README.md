# R2Yara module

This directory contains the source code for the r2 yara module.

By importing this module in your yara rules it is possible to use `radare2` to perform some advanced checks on the target binary.

## Author

This yara plugin was made in 2017 by @plutec and @mmorenog, see [ChangeLog.orig](ChangeLog.orig) the original commit history.

* Antonio Sanchez @plutec
* mmorenog @mmorenog

## Example

This is a very simple rule, but you can find more under the `rules` directory.

```
import "r2"
rule rule_intel_programs {
condition:
	r2.bins("x86", 64)
}
```

Note that right now, this module is just a JSON-like processor, that takes a report generated with an r2pipe script which is then feeded to yara like this:

```
$ ./generate_report.py binary > report.json
$ yara -x r2=report.json file.yar binary
```

## TODO

Note that this repository contains a copy of the original https://github.com/Yara-Rules/r2yara repository, which was not updated since 2017. So there are a bunch of things to improve. Moving the code under the `radareorg` umbrella is the first step towards this.

* [ ] Bring back the tests, but using r2r and don't use commited files
* [ ] Run r2 from inside yara, instead of depending on a JSON file
* [ ] Sync the code for the latest Yara (this module requires yara-3.6.3)
* [ ] Add makefile to simplify the use 

## Documentation

Read the documentation and examples of use: 

=> http://r2yara.readthedocs.io/en/latest/

[![Build Status](https://travis-ci.org/Yara-Rules/r2yara.svg)](https://travis-ci.org/Yara-Rules/r2yara)

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

