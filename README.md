cloud-crypt-diff-backup
--------------------

Tool to securely push incremental (think "rsync --link-dest") backups to cloud
storage services.

Under heavy development, not ready for general usage yet.


Idea
--------------------

Initial data should be a path (possibly detected as "latest" from provided
wildcard or regexp, think "/mnt/backups/myhost-*") and a cloud destination
(e.g. SkyDrive account credentials).

Tool should authorize with cloud service and retrieve database file (probably
just sqlite db), encrypted with a known symmetric key.

Caveats:

	* Key should probably auto-rotate on some schedule, to be useless for "just any"
		encrypted-db file that might get stolen at some point.

	* Compromise of a key and a cloud service credentials is fatal however, and
		that'd be the case if they're stored in the same configuration file.
		To fix that, some capability to initiate a backup (given encrypted-db) only
		from third-party might be implemented. DB can be encrypted with assymetic key
		in this case.

The database should contain a list of individual backed-up files, with following
data fields:

* Original file path in a backup.

* Destination path - path in a cloud storage.
	Can be derived from original by a secure hash function.

* File metadata - mtime, permissions, acls, xattrs, possibly even inode number.
	Used to restore metadata to backed-up state and to match against
	possibly-existing path on a filesystem that's being backed-up.

* Collision-resistant checksum of file contents.

* Possibly-unique authenticated-symmetric-encryption key for each one (though no
	extra care should be taken to ensure uniqueness, I guess), and a backup
	generation id.

Caveats:

	* Mostly-unique keys here should ensure that only compromise of the whole db
		will lead to compromise of all the files, not a compromise of any individual
		key.

	* db-stored and always-unique counter can be used as an IV (initialization
		vector) for encryption, so ciphertext of two files with identical content
		won't match.

	* Encryption keys should not be derived from each other in any predictable
		manner and probably always read straight from /dev/urandom, which I think
		should be seeded (esp. with ongoing disk/net activity during backup)
		reasonably often for that purpose.

If there are indeed files recorded in db, some (reasonably large) number of them
should be checked for existance and some smaller number should be downloaded to
check integrity (i.e. just decrypted with key, authenticated encryption
algorithm should take care of that).

If above integrity check is unsuccessfull, some warning notification should be
issued and backup either halted or continued in "from scratch" mode, possibly
checking whether each file exists in the cloud and it's integrity before upload.

Each file on backed-up fs should be checked against db and checksummed.
If checksum matches, file should only be recorded in a db, but without the
encryption key, to indicate that it's the same file as from previous backup
generation.
Otherwise it should be uploaded, then recorded in a db.

Uploaded filename should be derived from path (or possibly randomized) and
contents compressed (if file size is above some defined minimum, e.g. 512
bytes), then encrypted (some authenticated encryption algorithm) with an ad-hoc
key.
Encryption key and a destination path should be stored.

After each N uploads or M uploaded megabytes, free space check should be made
(possibly by just substracting each upload size from some cached value) and if
it falls below some defined threshold, oldest-generation backup files should be
removed.
Extra care (i.e. mandatory checks) should be taken not to remove files which are
referenced in newer-generation backups (i.e. checksum matches and no encryption
key recorded).

After that, db-file should be encrypted and uploaded as well.

Caveats:

	* Some periodic checks for missing files should also be performed - when
		there's a checksum in db with no corresponding encrypton key.

	* Deduplication on a per-file basis can be performed, if checksum is strong
		enough (i.e. several strong checksums are stored).

	* DB should also be returned to backup "requester" (see previous caveats).
		In fact, it might be wise not to store db itself in the cloud storage at all.

	* To ensure that it won't get lost (which would render all backups in the
		cloud storage unreadable), db can also be encrypted with asymmetrical key
		(e.g. gpg) and replicated elsewhere.

	* Some uploaded files might be larger than the filesize limit in the cloud, so
		"destination name" should contain sequence of several names, for each
		uploaded part.
		File checksum should be calculated for the whole contents, but integrity of
		each part can still be checked individually, since the check should be
		performed by authenticated encryption algorithm.


Implementation details
--------------------

* Python script (tool) with a configuration file.

* pycryptopp seem to be the best bet for secure encrypton and hash-functions.

* Compression can (and should) be offloaded to an xz (configurable) subprocess,
	so checksumming and encryption may go in parallel with it.

* For several cloud destinations, tahoe-lafs should probably be a better option,
	as it adds erasure coding and has everything else distributed already taken
	care of.

	For just one destination, tahoe seem to add a lot of complexity (i.e. the need
	to install and configure fairly complex client), but I'm very unsure about
	whether it's a good reason not to use it.
