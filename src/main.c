#include "version.h"
#include "logger.h"
#include "oshd.h"
#include "oshd_conf.h"
#include "xalloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static char *conf_file = NULL;

void print_version(void)
{
    printf("oshd %i.%i.%i-" OSH_COMMIT_HASH "\n",
        OSH_VERSION_MAJOR, OSH_VERSION_MINOR, OSH_VERSION_PATCH);
}

void print_help(const char *cmd)
{
    printf("Usage: %s [-h] [-V] [-d what] [-g file] config_file\n\n", cmd);
    printf("Description:\n");
    printf("    -h          Display this help and exit\n");
    printf("    -V          Display the program version and exit\n");
    printf("    -d what     Debug a part of the daemon, this can be:\n");
    printf("                  ");
    for (debug_what_t i = 0; i < debug_what_size; ++i) {
        printf("%s", logger_get_debug_name(i));
        if ((i + 1) < debug_what_size) {
            if ((i + 1) % 6 == 0) {
                printf(",\n                  ");
            } else {
                printf(", ");
            }
        } else {
            printf("\n\n");
        }
    }
    printf("    -g file     Generate Ed25519 keys to file.key and file.pub\n");

    printf("\n");
    printf("config_file: Path to the configuration file for the daemon\n");
    printf("             If omitted the file defaults to \"oshd.conf\"\n");
}

static bool generate_keys_to_file(const char *filename)
{
    const size_t filename_len = strlen(filename);
    const size_t outfile_len = filename_len + 5; // .pub or .key + '\0'
    char *outfile = xzalloc(outfile_len);
    bool success = false;
    EVP_PKEY *pkey;

    printf("Generating Ed25519 keys...\n");
    pkey = pkey_generate_ed25519();
    if (pkey) {
        snprintf(outfile, outfile_len, "%s.key", filename);
        printf("Writing private key to '%s'...\n", outfile);
        if (pkey_save_privkey_pem(pkey, outfile)) {
            snprintf(outfile, outfile_len, "%s.pub", filename);
            printf("Writing public key to '%s'...\n", outfile);
            success = pkey_save_pubkey_pem(pkey, outfile);
        }

    }
    free(outfile);
    if (success) printf("Successfully generated Ed25519 keys\n");
    return success;
}

void parse_args(int ac, char **av)
{
    const char shortopts[] = "hVd:g:";
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

            case 'g':
                exit(generate_keys_to_file(optarg) ? EXIT_SUCCESS : EXIT_FAILURE);

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