#include "version.h"
#include "logger.h"
#include "oshd.h"
#include "oshd_conf.h"
#include "xalloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static const char *av_cmd = NULL;

#define default_conf_file "oshd.conf"
static char *conf_file = NULL;
static char *keysdir = NULL;

static bool stop_after_conf_loaded = false;

static const char shortopts[] = "hVd:g:t";
static const struct option longopts[] = {
    {"help",                no_argument,        NULL, 'h'},
    {"version",             no_argument,        NULL, 'V'},
    {"debug",               required_argument,  NULL, 'd'},
    {"generate-keypair",    required_argument,  NULL, 'g'},
    {"test-config",         no_argument,        NULL, 't'},
    {"keysdir",             required_argument,  NULL, 256},
    {NULL,                  0,                  NULL,  0 }
};

// Indentation for descriptions (30 characters)
#define help_indent "                              "

// Format for argument + description on a single line
#define help_arg    "  %-27s %s\n"

// Format for argument + description on multiple lines (if argument is too big
// and overlaps with the description)
#define help_argnl  "  %s\n" help_indent "%s\n"

static void print_help(const char *cmd)
{
    printf("Usage: %s [-h] [options] config_file\n\n", cmd);
    printf("Description:\n");
    printf(help_arg,
        "-h, --help",
        "Display this help and exit");
    printf(help_arg,
        "-V, --version",
        "Display the program version and exit");

    // Print all the possible debug options
    // TODO: Make a better display
    const int debug_what_columns = 3;

    printf(help_arg,
        "-d, --debug=OPT1[,OPT2...]",
        "Log debugging information for parts of the daemon:");
    for (debug_what_t i = 0; i < debug_what_size; ++i) {
        if (i % debug_what_columns == 0)
            printf(help_indent "  ");

        printf("%-16s", logger_get_debug_name(i));

        if ((i + 1) >= debug_what_size) {
            printf("\n\n");
        } else if ((i + 1) % debug_what_columns == 0) {
            printf("\n");
        }
    }

    printf(help_argnl,
        "-g, --generate-keypair=FILE",
        "Generate Ed25519 keys to FILE.key and FILE.pub\n");

    printf(help_arg,
        "-t, --test-config",
        "Load the configuration and exit");
    printf(help_indent "  Returns 0 on success, 1 on error\n");

    printf("\n");
    printf(help_arg, "--keysdir=DIR", "Set the keys directory to DIR");
    printf(help_indent "  Defaults to the working directory\n");

    printf("\n");
    printf("config_file: Path to the configuration file for the daemon\n");
    printf("             Defaults to \"" default_conf_file "\"\n");
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

static void parse_opt(int opt)
{
    switch (opt) {
        case 'h':
            print_help(av_cmd);
            exit(EXIT_SUCCESS);

        case 'V':
            printf(OSH_VERSION_FMT "\n", OSH_VERSION_FMT_ARGS);
            exit(EXIT_SUCCESS);

        case 'd': {
            bool success = true;
            char *dbg_dup = xstrdup(optarg);
            char *dbg_tok = strtok(dbg_dup, ",");

            while (dbg_tok) {
                if (!(success = logger_toggle_debug_name(dbg_tok))) {
                    fprintf(stderr, "Invalid debug option: '%s'\n", dbg_tok);
                    break;
                }
                dbg_tok = strtok(NULL, ",");
            }
            free(dbg_dup);
            if (!success)
                exit(EXIT_FAILURE);
            break;
        }

        case 'g':
            exit(generate_keys_to_file(optarg) ? EXIT_SUCCESS : EXIT_FAILURE);

        case 't':
            stop_after_conf_loaded = true;
            break;

        case 256:
            keysdir = optarg;
            break;

        default: exit(EXIT_FAILURE);
    }
}

void parse_args(int ac, char **av)
{
    int opt;
    int opt_val;

    av_cmd = av[0];

    while ((opt = getopt_long(ac, av, shortopts, longopts, &opt_val)) > 0)
        parse_opt(opt);

    if (optind < ac) {
        conf_file = av[optind];
    } else {
        conf_file = default_conf_file;
    }
}

int main(int ac, char **av)
{
    parse_args(ac, av);

    atexit(oshd_free);
    oshd_init_conf();

    if (keysdir)
        oshd_conf_set_keysdir(keysdir);

    if (!oshd_load_conf(conf_file))
        return EXIT_FAILURE;
    if (stop_after_conf_loaded) {
        logger(LOG_INFO, "%s: Ok", conf_file);
        return EXIT_SUCCESS;
    }

    if (!oshd_init())
        return EXIT_FAILURE;

    oshd_loop();
    return EXIT_SUCCESS;
}