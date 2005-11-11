package Apache2::AuthColloquy;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

use MD5;
use mod_perl2;

require Exporter;

@ISA = qw(Exporter AutoLoader);
@EXPORT = qw();
$VERSION = sprintf('%d.%02d', q$Revision: 1.5 $ =~ /(\d+)/g);

# test for the version of mod_perl, and use the appropriate libraries
require Apache2::Access;
require Apache2::Connection;
require Apache2::Log;
require Apache2::RequestRec;
require Apache2::RequestUtil;
use Apache2::Const -compile => qw(HTTP_UNAUTHORIZED OK DECLINED);

# Handles Apache requests
sub handler {
	my $r = shift;

	my ($result, $password) = $r->get_basic_auth_pw;
	return $result if $result;

	my $user = $r->user;
	my $users_lua = $r->dir_config('users_lua') || '/usr/local/colloquy/data/users.lua';
	my $allowaltauth = $r->dir_config('AllowAlternateAuth') || 'no';

	# remove the domainname if logging in from winxp
	## Parse $name's with Domain\Username
	my $domain = '';
	if ($user =~ m|(\w+)[\\/](.+)|) {
		($domain, $user) = ($1, $2);
	}

	# Check we have a password
	unless (length($password)) {
		$r->note_basic_auth_failure;
		$r->log_error("user $user: no password supplied", $r->uri);
		return Apache2::Const::HTTP_UNAUTHORIZED;
	}

	# Check the database file exists
	unless (-f $users_lua) {
		$r->note_basic_auth_failure;
		$r->log_error(
			"user $user: no such users_lua database file: $users_lua",
			$r->uri);
		return (lc($allowaltauth) eq "yes" ? Apache2::Const::DECLINED : Apache2::Const::HTTP_UNAUTHORIZED);
	}

	# In the future, add a check to ensure that the users.lua file
	# does not have world write permissions set.
	#
	#
	#

	# Check we can read the database file
	unless (-r $users_lua) {
		$r->note_basic_auth_failure;
		$r->log_error(
			"user $user: unable to read users_lua database file: $users_lua",
			$r->uri);
		return (lc($allowaltauth) eq "yes" ? Apache2::Const::DECLINED : Apache2::Const::HTTP_UNAUTHORIZED);
	}

	# Read the database file
	my $users = _get_data($users_lua);

	# Check we have found that user
	unless (exists $users->{"$user"}->{password2}) {
		$r->note_basic_auth_failure;
		$r->log_error(
			"user $user: invalid password",
			$r->uri);
		return (lc($allowaltauth) eq "yes" ? Apache2::Const::DECLINED : Apache2::Const::HTTP_UNAUTHORIZED);
	}

	# Now check the password
	my $db_password_hash = $users->{"$user"}->{password2} || '_no_db_passd_';
	my $our_password_hash = MD5->hexhash("$user$password") || '_no_usr_passd_';
	if ($our_password_hash eq $db_password_hash) {
		return Apache2::Const::OK;
	} else {
		return (lc($allowaltauth) eq "yes" ? Apache2::Const::DECLINED : Apache2::Const::HTTP_UNAUTHORIZED);
	}

	# Otherwise fail
	return (lc($allowaltauth) eq "yes" ? Apache2::Const::DECLINED : Apache2::Const::HTTP_UNAUTHORIZED);
}

sub _get_data {
	my $users_lua = shift;
	my $users = {};
	if (open(FH,"<$users_lua")) {
		local $/ = undef;
		my $coderef = <FH>;
		close(FH);
		$coderef = "\$$coderef;";
		$coderef =~ s/'/\\'/g;
		$coderef =~ s/"/'/g; #"'
		$coderef =~ s/(\s+[a-z0-9]+\s+=)(\s+['{\d+])/$1>$2/gi;
		eval $coderef;
	}
	return $users;
}

1;

=pod

=head1 NAME

Apache2::AuthColloquy - mod_perl module that allows authentication against the Colloquy users.lua file

=head1 SYNOPSIS

 AuthName "Talker Members Area"
 AuthType Basic

 # Full path to your users.lua file
 PerlSetVar users_lua /home/system/colloquy/data/users.lua

 # Set if you want to allow an alternate method of authentication
 PerlSetVar AllowAlternateAuth yes | no

 require valid-user
 PerlAuthenHandler Apache2::AuthColloquy

=head1 DESCRIPTION

Apache2::AuthColloquy is an Apache 2 authentication module. It will
authenticate against a Colloquy users.lua user database file using
the newer password2 field.

This script munges the users.lua file in to executable perl code
which is then evaluated. It should therefore be used with caution
if you cannot gaurentee the integrity of the users.lua file.

=head1 VERSION

$Revision: 1.5 $

=head1 AUTHOR

Nicola Worthington <nicolaw@cpan.org>

http://www.nicolaworthington.com

$Author: nicolaw $

=cut

__END__


