# linux-vault

linux-vault locks a folder in your home. While it is unlocked the folder is ordinary files. Lock packs it into one encrypted 7z archive and marks that archive immutable. Unlock asks for the passphrase and turns it back into a folder.

The command is `lve`. The passphrase is typed into pinentry, not into the terminal. You can have more than one vault. Each has its own passphrase, and the folder shows up in the Nautilus bookmarks.

A vault name that belongs to someone else is the same error as a name that does not exist: `org.linuxvault.Error.NotFound`, with the text `vault not found`. `lve` exits 11. `lve ls` lists only your vaults.

It's built for Fedora and installs as an RPM. 7-Zip and pinentry-qt are installed with it.

The app isn't finished yet.
