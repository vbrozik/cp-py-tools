# Plans for future tools and features

## New tools

- Installer script - for installing and updating the tools

## cpsftp

- Extend filters - e.g. list files from today
- Add issue title as an account property
- Do not show full exception backtrace by default
- Allow to specify a HTTP proxy per SFTP account
- Add synchronization between Gaia machines (probably through the management server, using `cprid_util`)
- Probably verify the uploaded file sizes by default and add `--verify` option to also download and verify the contents
- Add recursive `ls` command
- Show warning if communication fails and `/proc/self/nsid` does not contain `0` (VSX context other that VS0)
- Work with time zones
- Add warning that the account or password has probably expired
- Show progress for file transfer
- Add filters for uploads (e.g. upload only today's files)
- Add function to wait for new files to stop changing or to appear
- Write tests
- Split `curl` code into a separate module
- Add password encryption using for example `openssl enc` (on Gaia `$CPDIR/bin/cpopenssl`).
- Add option to rename uploaded files.
- Add option to rename uploaded files automatically (e.g. add a timestamp and hostname).
- Add option to create an archive of the uploaded files.
- Add command sr-import to import all or selected exported SFTP accounts.
- Add option to run a command and the upload its output.
- Add support for sftp protocol, including HTTP proxy support

### Bugs

- Commands do not detect error responses from the server. For example `get` does not detect:
  - `<html><head><title>Forbidden</title></head><body><H1>HTTP/1.1 403 Forbidden</H1></body></html>`
