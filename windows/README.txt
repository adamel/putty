PuTTY GSS-API keyex README
==========================

This is the README file for the PuTTY GSS-API keyex installer
distribution. It contains the following features not present
in the upstream PuTTY:

* Support for GSS-API key exchange and gssapi-keyex authentication.
* Support for Heimdal GSS-API.
* 64-bit binaries and installer.
* Data Execution Prevention enabled for all binaries.
* Binaries and installer signed using Microsoft Authenticode.

The PuTTY GSS-API keyex home is

    https://marcussundberg.com/putty/


PuTTY README
============

This is the README file for the PuTTY installer distribution. If
you're reading this, you've probably just run our installer and
installed PuTTY on your system.

What should I do next?
----------------------

If you want to use PuTTY to connect to other computers, or use PSFTP
to transfer files, you should just be able to run them from the
Start menu.

If you want to use the command-line-only file transfer utility PSCP,
you will probably want to put the PuTTY installation directory on
your PATH. On Windows 7 and similar versions, you can do this at
Control Panel > System and Security > System > Advanced system
settings > Environment Variables.

Some versions of Windows will refuse to run HTML Help files (.CHM)
if they are installed on a network drive. If you have installed
PuTTY on a network drive, you might want to check that the help file
works properly. If not, see http://support.microsoft.com/kb/896054
for information on how to solve this problem.

What do I do if it doesn't work?
--------------------------------

The PuTTY home web site is

    http://www.chiark.greenend.org.uk/~sgtatham/putty/

Here you will find our list of known bugs and pending feature
requests. If your problem is not listed in there, or in the FAQ, or
in the manuals, read the Feedback page to find out how to report
bugs to us. PLEASE read the Feedback page carefully: it is there to
save you time as well as us. Do not send us one-line bug reports
telling us `it doesn't work'.
