# psh

*See [docs.rs](https://docs.rs/psh/latest/psh/) page for crate documentation and examples.*

*psh* is a deterministic password derivation and management library and a CLI tool that's built upon
it. It is the fusion of two different approaches to password management aiming to be as secure as
possible.

One approach is a ubiquitous password manager software like KeePass which has disadvantages of 1)
relying on a single master password to rule them all and 2) difficult-to-do-it-secure DB
synchronization between devices.

Another approach is a deterministic password generation like [pwcalc](https://github.com/pmorjan/pwcalc-chrome)
which, if not used with strong secret words, produces passwords that are easy to guess.

*psh* combines both approaches and generates deterministic passwords (which eliminates the necessity
to synchronize password database), using three inputs: master password, alias and a secret word.
Use of master password removes the requirement for a secret word to be strong (*psh* even allows to
not use it), so user can choose easily memorable alias and secret word without compromising
security. *psh* uses Argon2 algorithm to generate passwords, which makes it harder to guess passwords
even if part of input values is known. Aliases, that was previously used (along with selected
character set for password generation) are stored in a database, so user don't need to select
character set each time a password is being generated, and they are encrypted.

![](/psh.gif "")

## Principle scheme

![](/psh.png "")

## TODO

* Build Android app
* Integrate with `keyutils`/`libsecret`

## Other notes

I write this code as a part of my study of Rust, it's not perfect, can contain critical security
bugs, and the whole idea can be flawed.
