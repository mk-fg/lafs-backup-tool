lafs-backup-tool
--------------------

Tool to securely push incremental (think "rsync --link-dest") backups to [Tahoe
Least Authority File System](https://tahoe-lafs.org/).

Under heavy development, not ready for general usage yet.


Idea
--------------------

Use-case is to push most important (chosen by human) parts of already existing
and static backups (stored as file trees) to lafs cloud backends.

Excellent [GridBackup project](https://github.com/divegeek/GridBackup) seem to
be full of backup-process wisdom, but also more complexity and targetted at a
bit more (and much more complex) use-cases.

tahoe_backup.py script, shipped with tahoe-lafs already does most of what I
want, missing only the following features:

* Compression.

	It has obvious security implications, but as I try hard to exclude
	non-compressible media content from backups, and given very limited amount of
	cloud-space I plan to use, advantages are quite significant.

	xz (lzma2) compression is usually deterministic, but I suppose it might break
	occasionally on updates, forcing re-upload of all the files.

	See also: [compression
	tag](https://tahoe-lafs.org/trac/tahoe-lafs/query?status=!closed&keywords=~compression&order=priority),
	[#1354](https://tahoe-lafs.org/trac/tahoe-lafs/ticket/1354).

* Metadata.

	ACLs (and some other xattrs) can and should be properly serialized and added
	to filesystem edges, if present.

* Symlinks.

	Backup these as a small files (containing destination path) with a special
	metadata mark (no mode).

	See also: [#641](https://tahoe-lafs.org/trac/tahoe-lafs/ticket/641).

* Include / exclude regexp lists, maintained by hand.

* More verbose logging

	Especially the timestamps, info about compression and deduplication (which
	files change), to be able to improve system performance, if necessary.
