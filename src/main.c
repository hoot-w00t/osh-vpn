#include "base64.h"
#include "version.h"
#include "logger.h"
#include "oshd.h"
#include "oshd_conf.h"
#include "xalloc.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

static const char *av_cmd = NULL;

#define default_conf_file "oshd.conf"
static char *conf_file = NULL;

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
        "Read a private key from FILE and print the associated public key\n");

    printf(help_arg,
        "-t, --test-config",
        "Load the configuration and exit");
    printf(help_indent "  Returns 0 on success, 1 on error\n");

    printf("\n");
    printf("config_file: Path to the configuration file for the daemon\n");
    printf("             Defaults to \"" default_conf_file "\"\n");
}

// --generate-key
static bool generate_key(void)
{
    uint8_t *privkey = NULL;
    size_t privkey_size = 0;
    char *privkey64 = NULL;
    EVP_PKEY *pkey = NULL;
    bool success = false;

    // Generate the private key
    if (!(pkey = pkey_generate_ed25519()))
        goto end;

    // Save it to memory
    if (!pkey_save_privkey(pkey, &privkey, &privkey_size))
        goto end;

    // Encode it in Base64 and print it to stdout
    privkey64 = xzalloc(BASE64_ENCODE_OUTSIZE(privkey_size));
    base64_encode(privkey64, privkey, privkey_size);
    printf("%s\n", privkey64);
    success = true;

end:
    free(privkey);
    free(privkey64);
    pkey_free(pkey);
    return success;
}

// --generate-key-pem
static bool generate_key_pem(const char *filename)
{
    bool success;
    EVP_PKEY *pkey;

    // Generate the private key
    pkey = pkey_generate_ed25519();
    if (!pkey)
        return false;

    // Save it to filename
    success = pkey_save_privkey_pem(pkey, filename);
    if (success)
        printf("Generated private key to: %s\n", filename);

    pkey_free(pkey);
    return success;
}

// --public-key
static bool public_key(void)
{
    char privkey64[BASE64_ENCODE_EXACTSIZE(ED25519_KEY_SIZE)];
    size_t privkey64_size;
    uint8_t privkey[BASE64_DECODE_OUTSIZE(sizeof(privkey64))];
    size_t privkey_size;
    uint8_t *pubkey = NULL;
    size_t pubkey_size;
    char *pubkey64 = NULL;
    EVP_PKEY *pkey = NULL;
    bool success = false;

    // Read the Base64 encoded private key from stdin
    memset(privkey64, 0, sizeof(privkey64));
    privkey64_size = fread(privkey64, 1, sizeof(privkey64) - 1, stdin);
    if (privkey64_size < sizeof(privkey64) - 1) {
        fprintf(stderr, "Encoded private key is too short\n");
        goto end;
    }

    // Decode it
    if (!base64_decode(privkey, &privkey_size, privkey64, strlen(privkey64))) {
        fprintf(stderr, "Failed to decode Base64 private key\n");
        goto end;
    }

    // Load it
    if (!(pkey = pkey_load_ed25519_privkey(privkey, privkey_size))) {
        fprintf(stderr, "Failed to load private key\n");
        goto end;
    }

    // Save the public key to memory
    if (!pkey_save_pubkey(pkey, &pubkey, &pubkey_size)) {
        fprintf(stderr, "Failed to save public key\n");
        goto end;
    }

    // Encode it in Base64 and print it to stdout
    pubkey64 = xzalloc(BASE64_ENCODE_OUTSIZE(pubkey_size));
    base64_encode(pubkey64, pubkey, pubkey_size);
    printf("%s\n", pubkey64);
    success = true;

end:
    free(pubkey);
    free(pubkey64);
    pkey_free(pkey);
    return success;
}

// --public-key-pem
static bool public_key_pem(const char *filename)
{
    EVP_PKEY *pkey = NULL;
    uint8_t *pubkey = NULL;
    size_t pubkey_size;
    char *pubkey64 = NULL;
    bool success = false;

    // Load the private key from filename
    if (!(pkey = pkey_load_privkey_pem(filename)))
        goto end;

    // Save the public key to memory
    if (!pkey_save_pubkey(pkey, &pubkey, &pubkey_size)) {
        fprintf(stderr, "Failed to save public key\n");
        goto end;
    }

    // Encode it in Base64 and print it to stdout
    pubkey64 = xzalloc(BASE64_ENCODE_OUTSIZE(pubkey_size));
    base64_encode(pubkey64, pubkey, pubkey_size);
    printf("%s\n", pubkey64);
    success = true;

end:
    free(pubkey);
    free(pubkey64);
    pkey_free(pkey);
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