# Fuzz-introspector config

## Code exclusion from the report
Fuzz-introspector accepts a config file that is used for defining content that
should be excluded from the analysis. This is useful, for example, to avoid
including third-party libraries or similar in the analysis, but rather focus
on the code that is of interest.

The config file is triggered to be used by setting the `FUZZ_INTROSPECTOR_CONFIG`
environment variable to the filename of the config file.

The config file is simple: it takes function names and file paths that should
be excluded from the analysis. The function names and file paths are specified
as regexes following [POSIX notation](https://www.boost.org/doc/libs/1_38_0/libs/regex/doc/html/boost_regex/syntax/basic_extended.html)

The notation of the config file is simple. Two keywords are used `FUNCS_TO_AVOID` and
`FILES_TO_AVOID`. These are followed by a set of regular expressions that indicate
teh function names and files to exclude, respectively.

An example file:
```
FUNCS_TO_AVOID
someFunctionRegex
FILES_TO_AVOID
libxml2
```

This file excludes all functions that are matched by the regex `someFunctionRegex` 
and also all files that have `libxml2` in the file path.

Fuzz-introspector already excludes several functions by default, including many
standard C++ library functions.

## Limitations
The configuration file will only apply to data that is in the Fuzz-introspector HTML
reports. In particular, this means:
- The code coverage reports linked to by Fuzz-introspector will still show all the
  files that are in the coverage report which was used as input to Fuzz-introspector.
  In order to exclude certain files from the code coverage reports, it's needed to
  avoid instrumenting these files entirely.
