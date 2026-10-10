/* sudo's own parse_args, run on this process's argv as sudo's main runs it,
 * printing the mode and submit_optind the audit plugin's open() is given. */
#include <config.h>

#include <stdio.h>

#include <sudo.h>

/* What parse_args.c reaches in the rest of sudo's front end, none of which
 * bears on the mode. */
int get_net_ifs(char **addrinfo) { (void)addrinfo; return 0; }
bool gc_add(enum sudo_gc_types type, void *v) { (void)type; (void)v; return true; }
bool exec_ptrace_intercept_supported(void) { return false; }
bool exec_ptrace_subcmds_supported(void) { return false; }

int
main(int argc, char *argv[])
{
    const char * const allowed[] = { "sudo", "sudoedit", NULL };
    struct sudo_settings *settings;
    const char *list_user;
    char **nargv, **env_add;
    int optind, nargc;
    unsigned int mode;

    initprogname2(argc > 0 ? argv[0] : "sudo", allowed);
    mode = parse_args(argc, argv, "/bin/sh", &optind, &nargc, &nargv,
        &settings, &env_add, &list_user);
    printf("\noracle mode=%u optind=%d\n", mode & MODE_MASK, optind);
    return 0;
}
