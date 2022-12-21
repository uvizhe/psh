# Psh

*For preamble to design philosophy of this crate see GitHub
[project page](https://github.com/uvizhe/psh).*

`psh` is a password generator and a password manager library which produces deterministic
passwords for a set of user inputs. It can store previously used aliases and their password
derivation settings in encrypted form in its internal database at `$HOME/.psh.db`.

There is a binary target in this crate, a CLI utility that leverages `psh` functionality. It
can be installed using the following `cargo` command:
```sh
$ cargo install --features=cli psh
```

Below is an example of how to use `psh` in your code:
```rust
use psh::{Psh, ZeroizingString};

let master_password = ZeroizingString::new(
    "this_better_be_a_strong_password".to_string());
let psh = Psh::new(master_password)
    .expect("Error initializing Psh");
let alias = ZeroizingString::new(
    "my_secret_box".to_string());
let password = psh.derive_password(&alias, None, None);
```

For greater security it's possible to supply a secret:
```rust
# use psh::{Psh, ZeroizingString};
#
# let master_password = ZeroizingString::new(
#    "this_better_be_a_strong_password".to_string());
# let psh = Psh::new(master_password)
#    .expect("master password is too short");
# let alias = ZeroizingString::new(
#    "my_secret_box".to_string());
let secret = ZeroizingString::new(
    "an_easy_to_remember_secret_word".to_string());
let password = psh.derive_password(&alias, Some(secret), None);
```

The third argument to `derive_password()` is [`CharSet`]:
```rust
# use psh::{Psh, ZeroizingString};
use psh::CharSet;
#
# let master_password = ZeroizingString::new(
#    "this_better_be_a_strong_password".to_string());
# let psh = Psh::new(master_password)
#    .expect("master password is too short");
# let alias = ZeroizingString::new(
#    "my_secret_box".to_string());
// This password should consist of [a-zA-Z0-9] characters only
let password = psh.derive_password(&alias, None, Some(CharSet::Reduced));
```

To store/remove alias and its settings to/from `psh` database:
```rust
# use psh::{CharSet, Psh, ZeroizingString};
#
# let master_password = ZeroizingString::new(
#    "this_better_be_a_strong_password".to_string());
let mut psh = Psh::new(master_password)
   .expect("master password is too short");
# let alias = ZeroizingString::new(
#    "my_secret_box".to_string());
let use_secret = true;
let charset = CharSet::RequireAll;
// Store alias
psh.append_alias_to_db(&alias, Some(use_secret), Some(charset))
    .expect("Error storing alias");
// Remove alias
psh.remove_alias_from_db(&alias)
    .expect("Error removing alias");
```
