# LibHideIP #

LibHideIP, a library which hides your local IP address from programs.

The function replacements in LibHideIP first call the original functions
to do their job and then replace the returned data with generic data to
prevent leakage of sensitive information.

After that, the calling program can continue working as usual.

Read the info documentation (type `info doc/libhideip.info`) to get more
information.

Project homepage: <https://libhideip.sourceforge.io/>.

Author: Bogdan Drozdowski, bogdro (at) users . sourceforge . net

License: GPLv3+

## WARNING ##

The `dev` branch may contain code which is a work in progress and committed
just for tests. The code here may not work properly or even compile.

The `master` branch may contain code which is committed just for quality tests.

The tags, matching the official packages on SourceForge,
should be the most reliable points.
