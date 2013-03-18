lafs-backup-tool
--------------------

Tool to securely push incremental (think "rsync --link-dest") backups to [Tahoe
Least Authority File System](https://tahoe-lafs.org/).



Installation
--------------------

It's a regular package for Python 2.7 (not 3.X), but not in pypi, so can be
installed from a checkout with something like that:

	% python setup.py install

Better way would be to use [pip](http://pip-installer.org/) to install all the
necessary dependencies as well:

	% pip install 'git+https://github.com/mk-fg/lafs-backup-tool.git#egg=lafs-backup-tool'

Note that to install stuff in system-wide PATH and site-packages, elevated
privileges are often required.
Use "install --user",
[~/.pydistutils.cfg](http://docs.python.org/install/index.html#distutils-configuration-files)
or [virtualenv](http://pypi.python.org/pypi/virtualenv) to do unprivileged
installs into custom paths.

Alternatively, `./lafs-backup-tool` can be run right from the checkout tree,
without any installation.


### Requirements

* [Python 2.7 (not 3.X)](http://python.org) with sqlite3 support
* [layered-yaml-attrdict-config](https://github.com/mk-fg/layered-yaml-attrdict-config)
* [Twisted](http://twistedmatrix.com) (core components)
* [CFFI](http://cffi.readthedocs.org) (for fs ACL and capabilities support)
* (optional) [pyliblzma](https://launchpad.net/pyliblzma) - if xz compression is used

CFFI uses C compiler to generate bindings, so gcc (or other compiler) should be
available if you build module from source or run straight from checkout tree.
Some basic system libraries like "libacl" and "libcap" are used through CFFI
bindings and must be present in system at runtime and/or during build as well.



Usage
--------------------

First of all, make a copy of the [base
configuration](https://github.com/mk-fg/lafs-backup-tool/blob/master/lafs_backup/core.yaml)
(can be produced without comments by running `lafs-backup-tool dump_config`) and
set all the required settings there.
Untouched and uninteresting values can be stripped from there (reasonable
defaults from base config will be used), if only for the sake of clarity.

Resulting config file might look something like this:

	source:
	  path: /srv/backups/backup.*
	  queue:
	    path: /srv/backups/tmp/queue.txt
	  entry_cache:
	    path: /srv/backups/tmp/dentries.db

	filter:
	  - '+^/var/log/($|security/)' # backup only that subdir from /var/log
	  - '-^/var/(tmp|cache|log|spool)/'
	  - '-^/home/\w+/Downloads/'
	  - '-^/tmp/'

After that, backup process can be started with `lafs-backup-tool -c
<path_to_local_config> backup`.
When all files will be backed-up, LAFS URI of the backup root will be, unless
disabled in config, printed to stdout.

If/when old backup files will be removed from LAFS, `lafs-backup-tool cleanup`
command should be used to purge removed entries from deduplication cache
("entry_cache" settings), unless "disable_deduplication" option is used (in
which case no such cleanup is necessary).

`lafs-backup-tool list` command can be used to list finished backups, recorded
in "entry_cache" db file along with their URIs.
`lafs-backup-tool check` can run deep-check (and renew leases) on these.

CLI reference can be produced by running `lafs-backup-tool --help`.
For command-specific options, command in question must be specified,
e.g. `lafs-backup-tool backup -h`.

Additional info can be found in "Implementation details" section below.



Idea
--------------------

Intended use-case is to push most important (chosen by human) parts of already
existing and static backups (stored as file trees) to lafs cloud backends.

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
	occasionally on updates, forcing re-upload for some of the files.

	See also: [compression
	tag](https://tahoe-lafs.org/trac/tahoe-lafs/query?status=!closed&keywords=~compression&order=priority),
	[#1354](https://tahoe-lafs.org/trac/tahoe-lafs/ticket/1354).

* Metadata.

	Filesystem ACLs and Capabilities can and should be properly serialized and
	added to filesystem edges, if present on source filesystem.

* Symlinks.

	Backup these as a small files (containing destination path) with a special
	metadata mark (no mode).

	See also: [#641](https://tahoe-lafs.org/trac/tahoe-lafs/ticket/641).

* Include / exclude regexp lists, maintained by hand.

* More verbose logging

	Especially the timestamps, info about compression and deduplication (which
	files change), to be able to improve system performance, if necessary.

* Just a cleaner rewrite, as a base for any future ideas.

Some additional ideas that came after the initial implementation:

* Rate limiting.

	Necessary with free-cloud APIs, which tend to block too frequent requests, but
	might also be useful to reduce system load due to compression or crypto,
	network load.



Implementation details
--------------------

Only immutable lafs files/dirnodes are used at the moment, with the exception of
"append_to_lafs_dir" option, which updates list of backup caps in a mutable lafs
directory node.


##### Two-phase operation (of "backup" command)

* Phase one: generate queue-file with an ordered list of path of files/dirs and
	metadata to upload.

	Queue file is a human-readable line-oriented plaintext list with relative
	paths and fs metadata, like this:

		tmp/session_debug.log 1000:1000:100644
		tmp/root.log 0:0:100600//u::rwx,u:fraggod:rwx,g::r-x,m::rwx,o::r-x
		tmp 1000:1000:100755
		bin/skype_notify.sh 1000:1000:100755
		bin/fs_backup 1000:1000:2750/=;cap_dac_read_search+i
		bin 1000:1000:100755
		.netrc 1000:1000:100600
		 1000:1000:100755

	Format of each line is "path uid:gid:[mode][/caps[/acls]]".
	List is reverse-alpha-sorted.

* Phase two: read queue-file line-by-line and upload each file (checking if it's
	not uploaded already) or create a directory entry to/on the grid.

	Each uploaded node (and it's ro-cap) gets recorded in "entry_cache" sqlite db,
	keyed by all the relevant metadata (mtime, size, xattrs, file-path,
	contents-caps, etc), to facilitate both restarts and deduplication.

	It doesn't matter in fact if the next time this upload will be started from
	the same queue-file or another - same files won't be even considered for
	uploading.

	Note that such "already uploaded" state caching assumes that files stay
	healthy (i.e. available) in the grid. Appropriate check/repair tools should be
	used to ensure that that's the case (see "check" action below).

Phases can be run individually - queue-file can be generated with `--queue-only
[path]` and then just read (skipping (re-)generation) with `--reuse-queue
[path]` (or corresponding configuration file options).

Interrupted (for any reason) second phase of backup process (actual upload to
the grid) can be resumed by just restarting the operation.
`--reuse-queue` option may be used to speed things up a little (i.e. skip
building it again from the same files), but is generally unnecessary if
`source.queue.check_mtime` option is enabled (default).


##### Path filter

Very similar to rsync filter lists, but don't have merge (include other
filter-files) operations and is based on regexps, not glob patterns.

Represented as a list of exclude/include string-patterns (python regexps) to
match relative (to source.path, starting with "/") paths to backup, and must
start with '+' or '-' (that character gets stripped from regexp), to include or
exclude path, respectively.

Patterns are matched against each path in order they're listed.

Leaf directories are matched with the trailing slash (as with rsync) to be
distinguishable from files with the same name.
Matched by exclude-patterns directories won't be recursed into (can save a lot
of iops for cache and tmp paths).

If path doesn't match any regexp on the list, it will be included.

Example:

	- '+/\.git/config$'          # backup git repository config files
	- '+/\.git/info/'            # backup git repository "info" directory/contents
	- '-/\.git/'                 # *don't* backup/crawl-over any repository objects
	- '-/(?i)\.?svn(/|ignore)$'  # exclude (case-insensitive) svn (or .svn) dirs and ignore-lists
	- '-^/tmp/'                  # exclude /tmp path (but not "/subpath/tmp")

Note how ordering of these lines makes only some paths within ".git" directories
included, excluding the rest.

Also documented in [base
config](https://github.com/mk-fg/lafs-backup-tool/blob/master/lafs_backup/core.yaml).


##### Edge metadata

Tahoe-LAFS doesn't have a concept like "file inode" (metadata container) at the
moment, and while it's possible to emulate such thing with intermediate file,
it's also unnecessary, since arbitrary metadata can be stored inside directory
entries, beside link to the file contents.

Such metadata can be easily fetched from urls like
`http://tahoe-webapi/uri/URI:DIR2-CHK:.../?t=json` (see
docs/frontentds/webapi.rst).

Single filenode edge with metadata (dumped as YAML):

	README.md:
	  - filenode
	  - format: CHK
	    metadata:
	      enc: xz
	      gid: '1000'
	      mode: '100644'
	      uid: '1000'
	    mutable: false
	    ro_uri: URI:CHK:...
	    size: 1140
	    verify_uri: URI:CHK-Verifier:...

Metadata is stored in the same format as in the queue-file (described above).

One notable addtion to the queue-file data here is the "enc" key, which in
example above indicates that file contents are encoded using xz compression.
In case of compression (as with most other possible encodings), "size" field
doesn't indicate real (decoded) file size.


##### Compression

Configurable via similar pattern-matching mechanism as include/exclude filters
(`destination.encoding.xz.path_filter` list).

Filters here can be tuples like `[500, '\.(txt|csv|log)$']` to compress files
matching a pattern, but only if size is larger than the given value.
Otherwise syntax is identical ('+' or '-', followed by python regexp) to
`filter` config section (see above).

One operational difference from `filter` is that file size is taken into account
here, with small-enough files not being compressed, as it generally produces
larger output (for file sizes lesser than a few kilobytes, in case of xz
compression).
See `destination.encoding.xz.min_size` parameter.


##### Backup result

Result of the whole "queue and upload" operation is a single dircap to a root of
an immutable directory tree.

It can be printed to stdout (which isn't used otherwise, though logging can be
configured to use it), appended to some text file or be put into some
higher-level mutable directory (with a basename of a source path).

Other than that, it also gets recorded to "entry_cache" db along with generation
number for this particular backup, so that it can later be removed along with
all the files unique to it through the cleanup procedure.

See "destination.result" section of the [base
config](https://github.com/mk-fg/lafs-backup-tool/blob/master/lafs_backup/core.yaml)
for more info on these.


##### Where do lafs caps end up?

In some cases, it might be desirable to remove all keys to uploaded data, even
though it was read from local disk initially.

* "result" destination (stdout, file or some mutable tahoe dir - see above),
	naturally.

* Deduplication "entry_cache" db (path is required to be set in
  "source.entry_cache").

	That file is queried for the actual plaintext caps, so it's impossible to use
	hashed (or otherwise irreversibly-mapped) values there.

So if old data is to be removed from machine where the tool runs, these things
should be done:

* Resulting cap should be removed or encrypted (probably with assymetric crypto,
	so there'd be no decryption key on the machine), if it was stored on a local
	machine (e.g. appended to a file).
	If it was linked to a mutable tahoe directory, it should be unlinked.

	Provided "cleanup" command can remove caps from any configurable destinations
	(file, lafs dir), but only if configuration with regard to respective settings
	("append_to_file", "append_to_lafs_dir") didn't change since backup and entry
	in lafs dir was not renamed.

	Naturally, if cap was linked to some other directory node manually, it won't
	be removed by the command.

* "entry_cache" db removed or encrypted in a similar fashion or "cleanup"
	command is used.

	"cleanup" command gets generation number, corresponding to the backup root cap
	and removes all the items with that number.

	When item gets used in newer backup, it gets it's generation number bumped, so
	such operation is guaranteed to purge any entries used in this backup but not
	in any newer ones, which are guaranteed to stay intact.

* If any debug logging was enabled, these logs should be purged, as they may
	leak various info about the paths and source file/dir metadata.

One should also (naturally) beware of sqlite (if it doesn't get removed),
filesystem or underlying block device (e.g. solid-state drives) retaining the
thought-to-be-removed data.


##### Logging

Can be configured via config files (uses [python logging
subsystem](http://docs.python.org/library/logging.html)) and some CLI parameters
(for convenience - "--debug", "--noise").

"noise" level (which is lower than "debug") will have per-path logging (O(n)
scale), while output from any levels above should be independent of the file/dir
count.

Logs should never contain LAFS URIs/capabilities, but with "noise" level will
expose paths and some metadata information.


##### Twisted-based http client

I'm quite fond of [requests](http://docs.python-requests.org/en/latest/) module
myself, but ~~unfortunately it doesn't seem to provide streaming uploads of
large files at the moment~~ needed functionality wasn't there before.

Plus twisted is also a basis for tahoe-lafs implementation, so there's a good
chance it's already available (unlike gevent, used in requests.async /
grequests).
