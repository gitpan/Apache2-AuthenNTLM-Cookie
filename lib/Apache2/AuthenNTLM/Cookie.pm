package Apache2::AuthenNTLM::Cookie;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::Cookie;
use Apache2::Directive ();
use Apache2::Const -compile => qw(OK) ;

use Digest::SHA1  qw(sha1_hex);

use base 'Apache2::AuthenNTLM';

our $VERSION = '0.01';

my $PACK_STRING = "A40 A12 A*"; # digest(40); time_created(12); username

sub handler : method  {
  my ($class, $r) = @_ ;

  my $self = bless {
    request     => $r,
    secret      => $r->dir_config('secret')      || $class->default_secret,
    refresh     => $r->dir_config('refresh')     || 3600, # in seconds
    cookie_name => $r->dir_config('cookie_name') || 'NTLM_AUTHEN',
   }, $class;

  # get the cookie
  my $jar    = Apache2::Cookie::Jar->new($r);
  my $cookie = $jar->cookies($self->{cookie_name});

  # OK if cookie present and valid
  return Apache2::Const::OK 
    if $cookie and $self->validate_cookie($cookie->value);

  # otherwise, go through the NTLM handshake and then create the cookie
  $r->log->debug("AuthenNTLM::Cookie: calling SUPER (NTLM handler)");
  my $result = $class->SUPER::handler($r); # if success, will set $r->user
  $self->set_cookie if $result == Apache2::Const::OK;

  return $result;
}


sub validate_cookie : method {
  my ($self, $cookie_val) = @_;

  # unpack cookie information
  my ($sha, $time_created, $username) = unpack $PACK_STRING, $cookie_val;

  # valid if not too old and matches the SHA1 digest
  my $now = time;
  my $is_valid 
    =  ($now - $time_created) < $self->{refresh}
    && $sha eq sha1_hex($time_created, $username, $self->{secret});

  # if valid, set the username
  $self->{request}->user($username) if $is_valid;

  $self->{request}->log->debug("cookie $cookie_val is " . 
                                 ($is_valid ? "valid" : "invalid"));
  return $is_valid;
}


sub set_cookie : method {
  my ($self) = @_;

  # prepare a new cookie from current time and current user
  my $r           = $self->{request};
  my $username    = $r->user; # was just set from the parent handler
  my $now         = time;
  my $sha         = sha1_hex($now, $username, $self->{secret});
  my $cookie_val  = pack $PACK_STRING, $sha, $now, $username;
  my @cookie_args = (-name => $self->{cookie_name}, -value => $cookie_val);

  # other cookie args may come from apache config
 ARG:
  foreach my $arg (qw/expires domain path/) {
    my $val = $r->dir_config($arg) or next ARG;
    push @cookie_args, -$arg => $val;
  }

  # send cookie
  my $cookie = Apache2::Cookie->new($r, @cookie_args);
  $cookie->bake($r);

  $r->log->debug("AuthenNTLM::Cookie: baked cookie $cookie_val");
}


sub default_secret {
  my ($class) = @_;

  # default secret : mtime and i-node of Apache configuration file
  my $config_file     = Apache2::Directive::conftree->filename;
  my ($mtime, $inode) = (stat $config_file)[9, 1];  
  return $mtime . $inode;
}


1;


__END__



=head1 NAME

Apache2::AuthenNTLM::Cookie - Store NTLM identity in a cookie

=head1 SYNOPSIS

  <Location /my/secured/URL>
    PerlAuthenHandler Apache2::AuthenNTLM::Cookie
    AuthType ntlm
    PerlAddVar ntdomain "domain primary_domain_controller other_controller"
    ...    # see other configuration params in Apache2::AuthenNTLM
  </Location>

=head1 DESCRIPTION

This module extends  L<Apache2::AuthenNTLM> with a cookie mechanism.

The parent module L<Apache2::AuthenNTLM> performs user authentication
via Microsoft's NTLM protocol; thanks to this mechanism, users are
automatically recognized from their Windows login, without having to
type a username and password. The server does not have to be a Windows
machine : it can be any platform, provided that it has access to a
Windows domain controller.  On the client side, both Microsoft
Internet Explorer and Mozilla Firefox implement the NTLM protocol.

The NTLM handshake involves several packet exchanges, and furthermore
requires serialization through an internal semaphore. Therefore, 
in order to improve performance, the present module saves the result
of that handshake in a cookie, so that the next request gets an
immediate answer.

A similar module was already published on CPAN for Apache1 / modperl1 
(L<Apache::AuthCookieNTLM>). The present module is an implementation
for Apache2 / modperl2, and has a a different algorithm for cookie
generation, in order to prevent any attempt to forge a fake cookie.


=head1 CONFIGURATION

Configuration directives for NTLM authentication are 
just inherited from L<Apache2::AuthenNTLM>; see that module's
documentation. These are most probably all you need, namely
the minimal information for setting the handler, 
specifying the C<AuthType> and specifying the names
of domain controllers :

  <Location /my/secured/URL>
    PerlAuthenHandler Apache2::AuthenNTLM::Cookie
    AuthType ntlm
    PerlAddVar ntdomain "domain primary_domain_controller other_controller"
  </Location>

In addition to the inherited directives, some
optional C<PerlSetVar> directives 
allow you to control various details of cookie generation :

   PerlSetVar cookie_name my_cookie_name    # default is NTLM_AUTHEN
   PerlSetVar domain      my_cookie_domain  # default is none
   PerlSetVar expires     my_cookie_expires # default is none
   PerlSetVar path        my_cookie_path    # default is none
   PerlSetVar refresh     some_seconds      # default is 3600 (1 hour)
   PerlSetVar secret      my_secret_string  # default from stat(config file)

See L<Apache2::Cookie> for explanation of variables
C<cookie_name>, C<domain>, C<expires>, and C<path>.
The only variables specific to the present module are

=over

=item refresh

This is the number of seconds after which the cookie becomes invalid
for authentication : it complements the C<expires> parameter.  The
C<expires> value is a standard HTTP cookie mechanism which tells how
long a cookie will be kept on the client side; its default
value is 0, which means that this is a session cookie, staying as long
as the browser is open. But if the Windows account gets disabled,
the cookie will never reflect the new situation : therefore we 
must impose a periodic refresh of the cookie. The default refresh 
value is 3600 seconds (one hour).


=item secret

This is a secret phrase for generating a SHA1 digest that will be
incorporated into the cookie. The digest also incorporates the
username and cookie creation time, and is checked at each request :
therefore it is impossible to forge a fake cookie without knowing the
secret. 

The default value for the secret is the concatenation of modification
time and inode of the F<httpd.conf> file on the server; therefore if
the configuration file changes, authentication cookies are
automatically invalidated.

=back


=head1 AUTHOR

Laurent Dami, C<< <la_____.da__@etat.ge.ch> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-apache2-authenntlm-cookie at rt.cpan.org>, or through the web
interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Apache2-AuthenNTLM-Cookie>.
I will be notified, and then you'll automatically be notified of
progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Apache2::AuthenNTLM::Cookie

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Apache2-AuthenNTLM-Cookie>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Apache2-AuthenNTLM-Cookie>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Apache2-AuthenNTLM-Cookie>

=item * Search CPAN

L<http://search.cpan.org/dist/Apache2-AuthenNTLM-Cookie>

=back


=head1 TESTING NOTE

This module has no tests ... because I didn't manage to write 
command-line tests that would successfully load the APR dynamic
libraries. Any hints welcome! Nevertheless, the module
has been successfully tested on Apache2.2/modperl2/solaris.


=head1 COPYRIGHT & LICENSE

Copyright 2008 Laurent Dami, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of Apache2::AuthenNTLM::Cookie
