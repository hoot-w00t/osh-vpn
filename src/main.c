#include "version.h"
#include "logger.h"
#include "oshd.h"
#include "oshd_conf.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

static char *conf_file = NULL;

void print_version(void)
{
    printf("oshd %i.%i.%i-" OSH_COMMIT_HASH "\n",
        OSH_VERSION_MAJOR, OSH_VERSION_MINOR, OSH_VERSION_PATCH);
}

void print_help(const char *cmd)
{
    printf("Usage: %s [-h] [-V] [-d {what}] config_file\n\n", cmd);
    printf("Description:\n");
    printf("    -h          Display this help and exit\n");
    printf("    -V          Display the program version and exit\n");
    printf("    -d {what}   Debug a part of the daemon, this can be:\n");
    printf("                  ");
    for (debug_what_t i = 0; i < debug_what_size; ++i) {
        printf("%s%s", logger_get_debug_name(i),
            ((i + 1) < debug_what_size) ? ", " : "\n");
    }

    printf("\n");
    printf("config_file: Path to the configuration file for the daemon\n");
    printf("             If omitted the file defaults to \"oshd.conf\"\n");
}

void parse_args(int ac, char **av)
{
    const char shortopts[] = "hVd:";
    int opt;

    while ((opt = getopt(ac, av, shortopts)) >= 0) {
        switch (opt) {
            case 'h':
                print_help(av[0]);
                exit(EXIT_SUCCESS);

            case 'V':
                print_version();
                exit(EXIT_SUCCESS);

            case 'd':
                if (!logger_toggle_debug_name(optarg)) {
                    fprintf(stderr, "Invalid debug: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;

            default: exit(EXIT_FAILURE);
        }
    }

    if (optind < ac) {
        conf_file = av[optind];
    } else {
        conf_file = "oshd.conf";
    }
}

int main(int ac, char **av)
{
    parse_args(ac, av);

    atexit(oshd_free);
    oshd_init_conf();

    if (!oshd_load_conf(conf_file))
        return EXIT_FAILURE;
    if (!oshd_init())
        return EXIT_FAILURE;

    oshd_loop();
    return EXIT_SUCCESS;
}