#include "kreamlink.h"

#include <getopt.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

atomic_int kl_stop_requested = 0;

static void handle_signal(int sig) {
    (void)sig;
    kl_stop_requested = 1;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "kreamlink v%s - Minimalist WSS Reverse Tunnel & E2EE Relay (Linux / macOS)\n\n"
        "Usage:\n"
        "  %s -c <config.yaml> [overrides...]\n"
        "  %s hub  [-l 127.0.0.1:8080] [--path /api/v1/stream] [--tls-cert C --tls-key K]\n"
        "  %s recv -u wss://host/api/v1/stream -k <channel> -l 127.0.0.1:10022\n"
        "  %s send -u wss://host/api/v1/stream -k <channel> -t 127.0.0.1:22\n\n"
        "Options:\n"
        "  -c, --config <file>       Load YAML configuration file\n"
        "  -l, --listen <addr>       Listen address (Hub or Receiver permanent local port)\n"
        "  -u, --hub <url>           Hub WebSocket URL (ws:// or wss://)\n"
        "  -k, --channel <secret>    Shared channel token (used for pairing & E2EE)\n"
        "  -t, --target <addr>       Sender target address to expose (e.g. 127.0.0.1:22)\n"
        "      --path <ws_path>      Hub WebSocket path (default: /api/v1/stream)\n"
        "      --subprotocol <val>   Optional Sec-WebSocket-Protocol disguise header\n"
        "      --cookie <val>        Optional Cookie disguise header\n"
        "      --ua <val>            Optional User-Agent header\n"
        "      --tls-cert <file>     Optional Hub direct TLS cert (PEM)\n"
        "      --tls-key <file>      Optional Hub direct TLS key (PEM)\n"
        "      --insecure            Skip TLS certificate verification (testing only)\n"
        "      --heartbeat <sec>     Heartbeat interval in seconds (default: 15)\n"
        "      --wait-peer <ms>      Receiver wait timeout when sender offline (default: 5000)\n"
        "      --padding <bytes>     Max random padding bytes 0..256 (default: 192)\n"
        "  -v, --verbose             Enable debug logging\n"
        "  -h, --help                Show this help message\n",
        KREAMLINK_VERSION, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    kl_config_t cfg;
    kl_config_init(&cfg);

    /* Optional positional subcommand: hub | recv | send */
    int arg_start = 1;
    if (argc >= 2 && argv[1][0] != '-') {
        if (strcmp(argv[1], "hub") == 0) {
            cfg.mode = KL_MODE_HUB;
            arg_start = 2;
        } else if (strcmp(argv[1], "recv") == 0 || strcmp(argv[1], "receiver") == 0) {
            cfg.mode = KL_MODE_RECV;
            arg_start = 2;
        } else if (strcmp(argv[1], "send") == 0 || strcmp(argv[1], "sender") == 0) {
            cfg.mode = KL_MODE_SEND;
            arg_start = 2;
        } else {
            fprintf(stderr, "Unknown mode: %s\n", argv[1]);
            print_usage(argv[0]);
            return 1;
        }
    }

    enum {
        OPT_PATH = 1000,
        OPT_SUBPROTO,
        OPT_COOKIE,
        OPT_UA,
        OPT_TLS_CERT,
        OPT_TLS_KEY,
        OPT_INSECURE,
        OPT_HEARTBEAT,
        OPT_WAIT_PEER,
        OPT_PADDING
    };

    static struct option long_opts[] = {
        {"config",      required_argument, NULL, 'c'},
        {"listen",      required_argument, NULL, 'l'},
        {"hub",         required_argument, NULL, 'u'},
        {"channel",     required_argument, NULL, 'k'},
        {"target",      required_argument, NULL, 't'},
        {"path",        required_argument, NULL, OPT_PATH},
        {"subprotocol", required_argument, NULL, OPT_SUBPROTO},
        {"cookie",      required_argument, NULL, OPT_COOKIE},
        {"ua",          required_argument, NULL, OPT_UA},
        {"tls-cert",    required_argument, NULL, OPT_TLS_CERT},
        {"tls-key",     required_argument, NULL, OPT_TLS_KEY},
        {"insecure",    no_argument,       NULL, OPT_INSECURE},
        {"heartbeat",   required_argument, NULL, OPT_HEARTBEAT},
        {"wait-peer",   required_argument, NULL, OPT_WAIT_PEER},
        {"padding",     required_argument, NULL, OPT_PADDING},
        {"verbose",     no_argument,       NULL, 'v'},
        {"help",        no_argument,       NULL, 'h'},
        {0, 0, 0, 0}
    };

    /* Shift argv if subcommand was consumed */
    int sub_argc = argc - (arg_start - 1);
    char **sub_argv = argv + (arg_start - 1);
    sub_argv[0] = argv[0];

    int opt;
    while ((opt = getopt_long(sub_argc, sub_argv, "c:l:u:k:t:vh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'c':
                if (kl_config_load_yaml(&cfg, optarg) != 0) return 1;
                break;
            case 'l':
                if (kl_copy_setting(cfg.listen_addr, sizeof(cfg.listen_addr), optarg) != 0) goto invalid_option;
                break;
            case 'u':
                if (kl_copy_setting(cfg.hub_url, sizeof(cfg.hub_url), optarg) != 0) goto invalid_option;
                break;
            case 'k':
                if (kl_copy_setting(cfg.channel, sizeof(cfg.channel), optarg) != 0) goto invalid_option;
                break;
            case 't':
                if (kl_copy_setting(cfg.target_addr, sizeof(cfg.target_addr), optarg) != 0) goto invalid_option;
                break;
            case OPT_PATH:
                if (kl_copy_setting(cfg.ws_path, sizeof(cfg.ws_path), optarg) != 0) goto invalid_option;
                break;
            case OPT_SUBPROTO:
                if (kl_copy_setting(cfg.subprotocol, sizeof(cfg.subprotocol), optarg) != 0) goto invalid_option;
                break;
            case OPT_COOKIE:
                if (kl_copy_setting(cfg.cookie, sizeof(cfg.cookie), optarg) != 0) goto invalid_option;
                break;
            case OPT_UA:
                if (kl_copy_setting(cfg.user_agent, sizeof(cfg.user_agent), optarg) != 0) goto invalid_option;
                break;
            case OPT_TLS_CERT:
                if (kl_copy_setting(cfg.tls_cert, sizeof(cfg.tls_cert), optarg) != 0) goto invalid_option;
                break;
            case OPT_TLS_KEY:
                if (kl_copy_setting(cfg.tls_key, sizeof(cfg.tls_key), optarg) != 0) goto invalid_option;
                break;
            case OPT_INSECURE:
                cfg.insecure_tls = true;
                break;
            case OPT_HEARTBEAT:
                if (kl_parse_int(optarg, 1, INT_MAX, &cfg.heartbeat_sec) != 0) goto invalid_option;
                break;
            case OPT_WAIT_PEER:
                if (kl_parse_int(optarg, 0, INT_MAX, &cfg.wait_peer_ms) != 0) goto invalid_option;
                break;
            case OPT_PADDING:
                if (kl_parse_int(optarg, 0, KL_MAX_PADDING, &cfg.padding_max) != 0) goto invalid_option;
                break;
            case 'v':
                cfg.log_level = KL_LOG_DEBUG;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind != sub_argc) goto invalid_option;

    /* Infer hub mode if config only had listen/ws_path and no hub/channel */
    if (cfg.mode == KL_MODE_NONE && cfg.listen_addr[0] && !cfg.hub_url[0]) {
        cfg.mode = KL_MODE_HUB;
    }

    if (cfg.mode == KL_MODE_NONE) {
        fprintf(stderr, "Error: must specify mode (hub, recv, send) or -c <config.yaml>\n\n");
        print_usage(argv[0]);
        return 1;
    }

    kl_log_set_level(cfg.log_level);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if (cfg.mode == KL_MODE_HUB) {
        return kl_hub_run(&cfg) == 0 ? 0 : 1;
    }

    if (!cfg.hub_url[0] || !cfg.channel[0]) {
        KL_ERROR("Agent requires both hub URL (-u) and channel secret (-k)");
        return 1;
    }
    if (cfg.mode == KL_MODE_RECV && !cfg.listen_addr[0]) {
        KL_ERROR("Receiver mode requires local listen address (-l, e.g. 127.0.0.1:10022)");
        return 1;
    }
    if (cfg.mode == KL_MODE_SEND && !cfg.target_addr[0]) {
        KL_ERROR("Sender mode requires target address (-t, e.g. 127.0.0.1:22)");
        return 1;
    }

    kl_url_t url;
    char host[256];
    uint16_t port;
    if (kl_parse_url(cfg.hub_url, &url) != 0 ||
        (cfg.mode == KL_MODE_SEND && kl_parse_hostport(cfg.target_addr, host, sizeof(host), &port) != 0)) {
        KL_ERROR("Invalid Hub URL or target address");
        return 1;
    }

    return kl_agent_run(&cfg) == 0 ? 0 : 1;

invalid_option:
    fprintf(stderr, "Invalid command-line argument or value\n");
    return 1;
}
