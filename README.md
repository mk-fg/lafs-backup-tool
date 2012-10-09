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

* Just a cleaner rewrite, as a base for any future ideas.



Implementation details
--------------------

Only immutable files/dirnodes are used at the moment.


##### Two-phase operation.

* Phase one: generate queue-file with an ordered list of path of files/dirs and
	metadata to upload.

	Queue file is a human-readable text file with metadata, like this:

		bin/skype_notify.sh 1000:1000:100755
		bin/fs_backup 1000:1000:2750/=;cap_dac_read_search+i
		bin 1000:1000:100755
		tmp/root.log 0:0:100600//u::rwx,u:fraggod:rwx,g::r-x,m::rwx,o::r-x
		tmp/session_debug.log 1000:1000:100644
		tmp 1000:1000:100755
		.netrc 1000:1000:100600
		 1000:1000:100755

	Format of each line is "path uid:gid:[mode]/[posix_caps]/[acls]".

* Phase two: read queue-file line-by-line and upload each file (checking if it's
	not uploaded already) or create a directory entry to/on the grid.

	Each uploaded node (and it's ro-cap) gets recorded in "entry_cache" dbm file,
	keyed by all the relevant metadata (mtime, size, xattrs, file-path,
	contents-caps, etc), to facilitate both restarts and deduplication.

	It doesn't matter in fact if the next time this upload will be started from
	the same queue-file or another - same files won't be even considered for
	uploading.

	Note that such "already uploaded" state caching assumes that files stay
	healthy (i.e. available) in the grid. Appropriate check/repair tools should be
	used to assure that.

Phases can be run individually - queue-file can be generated with `--queue-only`
and then just read with `--reuse-queue [path]` (or corresponding configuration
file options).

Interrupted (due to any reason) second phase of backup process (actual upload to
the grid) can be resumed with `--reuse-queue`.


##### Path filter

Very similar to rsync filter lists, but don't have merge (include other
filter-files) operations and is based on regexps, not glob patterns.

Represented as a list of either tuples like "[action ('+' or '-'), regexp]" or
just exclude-patterns (python regexps) to match relative (to source.path,
starting with "/") paths to backup.

Patterns are matched against each path in order they're listed.

Leaf directories are matched with the trailing slash (as with rsync) to be
distinguishable from files with the same name.
Matched by exclude-patterns directories won't be recursed into (can save a lot
of iops for cache and tmp paths).

If path doesn't match any regexp on the list, it will be included.

Example:

	- ['+', '/\.git/config$']   # backup git repository config files
	- '/\.git/'                 # *don't* backup any repository objects
	- ['-', '/\.git/']          # exactly same thing as above (redundant)
	- '/(?i)\.?svn(/|ignore)$'  # exclude (case-insensitive) svn (or .svn) dirs and ignore-lists
	- '^/tmp/'                  # exclude /tmp path (but not "/subpath/tmp")

Also documented in [base
config](https://github.com/mk-fg/lafs-backup-tool/blob/master/lafs_backup/core.yaml).


##### Twisted-based http client

I'm quite fond of [requests](http://docs.python-requests.org/en/latest/)
module myself, but unfortunately it doesn't seem to provide streaming uploads
of large files at the moment.

Plus twisted is also a basis for tahoe-lafs implementation, so there's a good
chance it's already available (unlike gevent, used in requests.async /
grequests).
