# linux-vault

linux-vault locks a folder in your home. You use it like any other folder until you lock it. Lock encrypts the files with GnuPG, then marks them immutable so they can't be changed or deleted. Unlock asks for your passphrase and turns the folder back into normal files.

You can have more than one. Each vault has its own passphrase, and the folder shows up in the Nautilus bookmarks.

It's built for Fedora and installs as an RPM. GnuPG is installed with it.

The app isn't finished yet.
