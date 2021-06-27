# Ghidra FindCrypt
![Bug eyed Ghidra looks at complex algorithms](docs/findcrypt_logo.png)

[![Github status](https://github.com/TorgoTorgo/ghidra-findcrypt/actions/workflows/main.yml/badge.svg)](https://github.com/TorgoTorgo/ghidra-findcrypt/actions/workflows/main.yml)
[![Gitlab status](https://gitlab.com/Torgo/ghidra_findcrypt/badges/master/pipeline.svg)](https://gitlab.com/Torgo/ghidra_findcrypt/pipelines/master/latest)

This is a re-write of another [Ghidra FindCrypt](https://github.com/d3v1l401/FindCrypt-Ghidra/) script
as an auto analysis module. It also takes better advantage of the Ghidra
API to label found constants.

## Building

FindCrypt builds like a standard Ghidra module:

```bash
cd FindCrypt
GHIDRA_INSTALL_DIR=/path/to/Ghidra_PUBLIC... gradle
```

This will output a zip in the `FindCrypt/dist/` directory.

## Installing

You can either build it yourself (see above) or download
a zip from the [Github releases](https://github.com/TorgoTorgo/ghidra-findcrypt/releases) or [GitLab releases](https://gitlab.com/Torgo/ghidra_findcrypt/-/releases)

The extension can be installed into Ghidra like so:
- From the Project window hit `File` -> `Install extensions...`
- Click the green plus icon on the top right
- In the file browser that opens, select the zip
- Click OK and restart Ghidra

## Using

Once the script is installed, a new Analysis is added to the Auto Analyze window
called "Find Crypt", it's enabled by default and it's safe to re-run. If you have
an existing file, open the "Analysis" menu in the CodeBrowser tool and click
"Auto Analyze". Select the "Find Crypt" analysis from the list and click Analyze.

Once the analysis is complete, any found crypt constants will be labeled with
the algorithm they're associated with. You can find these labels in the "Labels"
folder in the Symbol Tree window. The labels are prefixed with `CRYPT_` to group
them together.

The analysis will also try to set the datatype for the found constants, but if
a datatype has been applied by another analysis module that other module will
take precedence.

A comment is always placed when a crypt constant is found to tell you the type
and the size of the constant, just in case the datatype wasn't applied.

