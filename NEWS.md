# Changes

## 3.5

* New keygen option: --repeats (-r), times to repeat passphrase prompt
* More explicit passphrase prompts
* Improved portability
* Fix various issues with enchive-mode.el
* Minor documentation and bug fixes

## 3.4

* New `--pinentry` (`-e`) global option. This is an alternative way to
  input passphrases. This allows smoother `enchive-mode.el` operation.
* New `ENCHIVE_FILE_EXTENSION` compile-time option
* Removed `ENCHIVE_RANDOM_DEVICE` compile-time option.
* Improved error messages.
* Various documentation and bug fixes.

## 3.3

* New `enchive-mode.el` for editing `.enchive` files in Emacs.
* Remove `help` command and add a man page
* New `PREFIX` make variable, with `install` and `uninstall` targets
* Various bug fixes.

## 3.2

* New `fingerprint` command and `--fingerprint` (`-i`) key generation
  option to help identify keys.

## 3.1

* Various bug fixes.

## 3.0

* File format locked down.
