#include "base64.h"
#include "version.h"
#include "logger.h"
#include "oshd.h"
#include "oshd_conf.h"
#include "xalloc.h"
#include "memzero.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

static const char *av_cmd = NULL;

#define default_conf_file "oshd.conf"
static const char *conf_file = NULL;

static bool stop_after_conf_loaded = false;

// Don't forget to update shortopts too!
static const char shortopts[] = "hVC:d:t";
static const struct option longopts[] = {
    {"help",                no_argument,        NULL, 'h'},
    {"version",             no_argument,        NULL, 'V'},
    {"workdir",             required_argument,  NULL, 'C'},
    {"debug",               required_argument,  NULL, 'd'},
    {"test-config",         no_argument,        NULL, 't'},
    {"generate-key",        no_argument,        NULL, 256},
    {"generate-key-pem",    required_argument,  NULL, 257},
    {"public-key",          no_argument,        NULL, 258},
    {"public-key-pem",      required_argument,  NULL, 259},
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
    printf(help_arg,
        "-C, --workdir=DIR",
        "Change the working directory to DIR");
    printf("\n");

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

    printf(help_arg,
        "-t, --test-config",
        "Load the configuration and exit");
    printf(help_indent "  Returns 0 on success, 1 on error\n\n");

    printf(help_arg,
        "--generate-key",
        "Generate a private key and print it in Base64");
    printf(help_arg,
        "--generate-key-pem=FILE",
        "Generate a private key and write it to FILE\n");

    printf(help_arg,
        "--public-key",
        "Read a private key in Base64 and print the associated public key");
    printf(help_arg,
        "--public-key-pem=FILE",
        "Read a private key from FILE and print the associated public key");

    printf("\n");
    printf("config_file: Path to the configuration file for the daemon\n");
    printf("             Defaults to \"" default_conf_file "\"\n");
}

// --generate-key
static bool generate_key(void)
{
    keypair_t *keypair = keypair_create_nofail(KEYPAIR_ED25519);
    char *privkey_b64 = NULL;
    bool success = false;

    if (!keypair_generate_random(keypair))
        goto end;

    privkey_b64 = keypair_get_private_key_b64(keypair);
    assert(privkey_b64 != NULL);
    success = true;
    printf("%s\n", privkey_b64);

end:
    keypair_destroy(keypair);
    if (privkey_b64)
        memzero_str_free(privkey_b64);
    return success;
}

// --generate-key-pem
static bool generate_key_pem(const char *filename)
{
    keypair_t *keypair = keypair_create_nofail(KEYPAIR_ED25519);
    bool success = false;

    if (!keypair_generate_random(keypair))
        goto end;

    if (!keypair_get_private_key_pem(keypair, filename))
        goto end;

    printf("Generated private key to: %s\n", filename);
    success = true;

end:
    keypair_destroy(keypair);
    return success;
}

// --public-key
static bool public_key(void)
{
    keypair_t *keypair = keypair_create_nofail(KEYPAIR_ED25519);
    const size_t privkey_b64_maxlen = BASE64_ENCODE_EXACTSIZE(KEYPAIR_ED25519_KEYLEN);
    const size_t privkey_b64_readlen = privkey_b64_maxlen - 1;
    char *privkey_b64 = xzalloc(privkey_b64_maxlen);
    size_t privkey_b64_len;
    char *pubkey_b64 = NULL;
    bool success = false;

    // Read the Base64 private key from stdin
    privkey_b64_len = fread(privkey_b64, 1, privkey_b64_readlen, stdin);
    if (privkey_b64_len < privkey_b64_readlen) {
        fprintf(stderr, "Private key is too short\n");
        goto end;
    }

    // Load it and dump the public key in Base64
    if (!keypair_set_private_key_base64(keypair, privkey_b64))
        goto end;

    pubkey_b64 = keypair_get_public_key_b64(keypair);
    if (!pubkey_b64)
        goto end;

    printf("%s\n", pubkey_b64);
    success = true;

end:
    keypair_destroy(keypair);
    memzero_free(privkey_b64, privkey_b64_maxlen);
    if (pubkey_b64)
        memzero_str_free(pubkey_b64);
    return success;
}

// --public-key-pem
static bool public_key_pem(const char *filename)
{
    keypair_t *keypair = keypair_create_nofail(KEYPAIR_ED25519);
    char *pubkey_b64 = NULL;
    bool success = false;

    if (!keypair_set_private_key_pem(keypair, filename))
        goto end;

    pubkey_b64 = keypair_get_public_key_b64(keypair);
    if (!pubkey_b64)
        goto end;

    printf("%s\n", pubkey_b64);
    success = true;

end:
    keypair_destroy(keypair);
    if (pubkey_b64)
        memzero_str_free(pubkey_b64);
    return success;
}

static void parse_opt(int opt)
{
    switch (opt) {
        case 'h':
            print_help(av_cmd);
            exit(EXIT_SUCCESS);

        case 'V':
            printf("Osh daemon %s", osh_version_str);
            if (osh_version_has_comment())
                printf(" (%s)", osh_version_comment);
            printf("\n");
            exit(EXIT_SUCCESS);

        case 'C':
            if (chdir(optarg) != 0) {
                fprintf(stderr, "Failed to enter directory: %s: %s",
                    optarg, strerror(errno));
                exit(EXIT_FAILURE);
            }
            break;

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

        case 't':
            stop_after_conf_loaded = true;
            break;

        case 256:
            exit(generate_key() ? EXIT_SUCCESS : EXIT_FAILURE);

        case 257:
            exit(generate_key_pem(optarg) ? EXIT_SUCCESS : EXIT_FAILURE);

        case 258:
            exit(public_key() ? EXIT_SUCCESS : EXIT_FAILURE);

        case 259:
            exit(public_key_pem(optarg) ? EXIT_SUCCESS : EXIT_FAILURE);

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
