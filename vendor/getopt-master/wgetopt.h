#pragma once

#include <wctype.h>
#include <stdio.h>
#include <string.h>

static int optind;
static int opterr = 1;
static int optopt;
static wchar_t *optarg;

static int
wgetopt(int argc, wchar_t * const argv[], const wchar_t *optstring)
{
    static int optpos = 1;
    const wchar_t *arg;

    /* Reset? */
    if (optind == 0) {
        optind = !!argc;
        optpos = 1;
    }

    arg = argv[optind];
    if (arg && wcscmp(arg, L"--") == 0) {
        optind++;
        return -1;
    } else if (!arg || arg[0] != L'-' || !iswalnum(arg[1])) {
        return -1;
    } else {
        const wchar_t *opt = wcschr(optstring, arg[optpos]);
        optopt = arg[optpos];
        if (!opt) {
            if (opterr && *optstring != ':')
                fprintf(stderr, "%S: illegal option: %C\n", argv[0], optopt);
            if (!arg[++optpos]) {
                optind++;
                optpos = 1;
            }
            return '?';
        } else if (opt[1] == L':') {
            if (arg[optpos + 1]) {
                optarg = (wchar_t *)arg + optpos + 1;
                optind++;
                optpos = 1;
                return optopt;
            } else if (argv[optind + 1]) {
                optarg = (wchar_t *)argv[optind + 1];
                optind += 2;
                optpos = 1;
                return optopt;
            } else {
                if (opterr && *optstring != ':')
                    fprintf(stderr, 
                            "%S: option requires an argument: %C\n", 
                            argv[0], optopt);
                if (!arg[++optpos]) {
                    optind++;
                    optpos = 1;
                }
                return *optstring == L':' ? L':' : L'?';
            }
        } else {
            if (!arg[++optpos]) {
                optind++;
                optpos = 1;
            }
            return optopt;
        }
    }
}
