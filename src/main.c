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
    printf("oshd %i.%i.%i (%s)\n", OSH_VERSION_MAJOR, OSH_VERSION_MINOR,
        OSH_VERSION_PATCH, OSH_COMMIT_HASH);
}

void print_help(const char *cmd)
{
    printf("Usage: %s [-h] [-V] [-v] [-d] config_file\n\n", cmd);
    printf("Description:\n");
    printf("    -h      Display this help and exit\n");
    printf("    -V      Display the program version and exit\n");
    printf("    -v      Increase verbosity (repeatable)\n");
    printf("    -d      Decrease verbosity (repeatable)\n\n");

    printf("config_file: Path to the configuration file for the daemon\n");
    printf("             If omitted the file defaults to \"oshd.conf\"\n");
}

void parse_args(int ac, char **av)
{
    const char shortopts[] = "hVv";
    int opt;

    while ((opt = getopt(ac, av, shortopts)) >= 0) {
        switch (opt) {
            case 'h':
                print_help(av[0]);
                exit(EXIT_SUCCESS);

            case 'V':
                print_version();
                exit(EXIT_SUCCESS);

            case 'v':
                logger_inc_level();
                break;

            case 'd':
                logger_dec_level();
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