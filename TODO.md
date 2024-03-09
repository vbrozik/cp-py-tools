# Plans for future tools and features

## New tools

- Installer script - for installing and updating the tools

## cpsftp

- Add `get` command
- Extend filters - e.g. list files from today
- Add issue title as an account property
- Add synchronization between Gaia machines (probably through the management server, using `cprid_util`)
- Probably verify the uploaded file sizes by default and add `--verify` option to also download and verify the contents
- Add recursive `ls` command
- Show warning if communication fails and `/proc/self/nsid` does not contain `0`
- Work with time zones
- Add warning that the account or password has probably expired
- Show progress for file transfer
- Add filters for uploads (e.g. upload only today's files)
- Add function to wait for new files to stop changing or to appear
- Write tests
- Split `curl` code into a separate module
- Add password encryption using for example `openssl enc` (on Gaia `$CPDIR/bin/cpopenssl`).
