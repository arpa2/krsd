# Demonstration of krsd

This demonstration uses TODOMVC, a common example used to demonstratie
remoteStorage and Unhosted principles.  It is available under a MIT
license on https://github.com/tastejs/todomvc and included here in a
modified form.

The current demonstration is not suited for CORS yet, so you will have
to serve these files as part of your website's static content.  Do not
forget to setup the filesystem extended attribute user.mime_type on
each of the files so the krsd knows how to deliver them.

To use this, you can run krsd as follows:

krsd -p 443 --debug -n krsd.domain.tld --ssl --key-path=/etc/ssl/private/krsd.domain.tld-2014.pem --cert-path=/etc/ssl/certs/krsd.domain.tld-2014.pem --ca-path=/etc/ssl/certs/cacert.org.pem

You should create a /home/domain.tld/user/remotestorage path for your user data,
and setup a .k5remotestorage file with the Kerberos Principal Name that gets
R/W access to the data underneath it.

And of course, you'll need to setup Kerberos, and tell your browser to
use it on this site.  This may involve whitelisting the domain being
accessed, in a browser-specific manner.

This work has been shown to work with Safari, FireFox and Chrome, all run
under Mac OS X, using the builtin Kerberos support of Mac OS X.

The work done to modify remoteStorage in this demo will be ported back to
the remoteStorage main line and offered.  But it will first be integrated
into GitHub location https://github.com/arpa2/remotestorage.js in a branch
named "http-implied-auth".

