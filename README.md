# DokuWiki Plugin: DokuCrypt2

This is a plugin for DokuWiki to support client side cryptography.

* https://www.dokuwiki.org/plugin:dokucrypt3
* Licence: GPL-3.0 (https://www.gnu.org/licenses/gpl-3.0)
* Author: Originally by By Scott Moser. Maintained by Thomas Schäfer (thomas@hilbershome.de). Previously maintained by Sherri Wheeler (dokucrypt2)

> **!! Warning:** This plugin should not replace a password manager or peer reviewed cryptography tools for high-priority use. Do not store mission critical type data with this plugin - I cannot be sure that the info is not cached by DokuWiki or the web browser.

> **!! This plugin is provided without warranty or guarantee of any kind. Use at your own discretion.**

## Usage

```
Hi world.  I have a secret.  Can you read it?
<SECRET>I like ice cream</SECRET>
```

When the user hits 'Save' (or a draft is attempted to be saved) a prompt will open, asking the user to enter a pass phrase key for the encryption. Once supplied, the encryption will be done in the browser and the encrypted text submitted to the server.

## Settings

This plugin includes configuration settings.

* `copytoclipboard` - If set to true, the plugin tries to copy the decrypted value to the clipboard.
* `hidepasswordoncopytoclipboard` - If set to true, the decrypted value will not be shown after being copied to the clipboard (see option 'copytoclipboard').

## ChangeLog

* 2025-10-15: Release of dokucrypt3, which has originally been an internal fork of dokucrypt2 with massive changes to the way encryption is handled. The resulting pull request would not be merged into the base repository (due to maintenance effort). So a new github repository `dokucrypt3` was created based on dokucrypt2 and the new encryption engine.
