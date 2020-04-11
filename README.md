![Build Status](https://github.com/serializingme/gpo-bypass/workflows/Main/badge.svg)

# GPO Bypass
## Introduction

This utility allows you to bypass Group Policy enforced controls on Firefox, especifically, it allows you to still install add-ons even if disabled
through GPOs. This tool only supports 64 bit versions of Firefox. Pre-compiled versions of the tool are available under the `dist` directory.

### Common

Static library containing common code used by both the library and injector components.

### Library

Dynamic Link Library responsible for diverting the Windows Registry reading execution flow to change some of the read values to the ones that don't
disable add-ons installation.

### Injector

This is the executable that injects the library into the newly created Firefox process.

## Build it Yourself

All code is written in C and can be built with MinGW. To compile you will likely need to use:

```
$ make clean all
```

The resulting binaries will be in the `build` directory.

## Licensing

All code is licensed under GNU/GPL version 3. Icons used have been created by [Everaldo](http://www.everaldo.com/).
