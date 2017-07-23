static const char *docs_usage[] = {
"usage enchive [-p|--pubkey <file>] [-s|--seckey <file>]",
#if ENCHIVE_OPTION_AGENT
"              [-a|--agent[=seconds]] [-A|--no-agent]",
#endif
#if ENCHIVE_OPTION_RANDOM_DEVICE
"              [-r|--random-device <file>] "
#else
"              "
#endif
"[--version] [--help]",
"              <command> [args]",
"",
"Commands (unique prefixes accepted):",
"  keygen        generate a new master keypair",
"  archive       archive using the public key",
"  extract       extract from an archive using the secret key",
"  fingerprint   print the master keypair fingerprint",
"",
"  -p, --pubkey <file>        set the public key file [~/.enchive.pub]",
"  -s, --seckey <file>        set the secret key file [~/.enchive.sec]",
#if ENCHIVE_OPTION_AGENT
"  -a, --agent[=seconds]      run key agent after reading a passphrase ["
     STR(ENCHIVE_AGENT_TIMEOUT) "]",
"  -A, --no-agent             don't run the key agent"
#  if ENCHIVE_AGENT_DEFAULT_ENABLED
    "",
#  else
    " (default)",
#  endif
#endif
#if ENCHIVE_OPTION_RANDOM_DEVICE
"  -r, --random-device <dev>  device for secure entropy ["
    STR(ENCHIVE_RANDOM_DEVICE) "]",
#endif
"  --version                  display version information",
"  --help                     display this usage information",
"",
"Enchive archives files by encrypting them to yourself using your",
"public key. It uses ChaCha20, Curve25519, and HMAC-SHA256.",
0};
