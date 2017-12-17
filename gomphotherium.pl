#!/usr/bin/env perl

# Copyright (C) 2017 Alex Schroeder <alex@gnu.org>

# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.

use Mojolicious::Lite;
use Mojo::JSON qw(decode_json encode_json);
use Mojo::Log;
use Crypt::PRNG qw(irand random_bytes_b64);
use Crypt::PBKDF2;
 
# FIXME: configure where the log should go
my $log = Mojo::Log->new;

# Code from http://blogs.perl.org/users/joel_berger/2012/10/a-simple-mojoliciousdbi-example.html

use Encode;
plugin Charset => {charset => 'utf-8'};

# connect to database
use DBI;
my $dbh = DBI->connect("dbi:SQLite:database.db","","") or $log->fatal("Could not connect to database");

# add helper methods for interacting with database
helper db => sub { $dbh };


# clients
helper create_clients_table => sub {
  my $c = shift;
  $c->db->do('CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY, client_id INTEGER UNIQUE, client_secret, name, website)');
};

app->create_clients_table;

helper register_client => sub {
  my $c = shift;
  my ($name, $website) = @_;
  # does the client already exist?
  my $sth = eval { $c->db->prepare('SELECT id, client_id, client_secret FROM clients WHERE name = ?') } || $log->fatal("Cannot select client from database");
  $sth->execute($name);
  my ($id, $client_id, $client_secret) = $sth->fetchrow_array;
  if (not $id) {
    $log->info("Registering new client '$name'");
    $client_id = irand;
    $client_secret = random_bytes_b64(45);
    $sth = eval { $dbh->prepare('INSERT INTO clients (name, website, client_id, client_secret) VALUES (?, ?, ?, ?)') } || $log->fatal("Cannot insert client into database");
    $sth->execute($name, $website, $client_id, $client_secret);
    # fetch generated id
    $sth = eval { $c->db->prepare('SELECT id FROM clients WHERE name = ?') } || $log->fatal("Cannot select new client id from database");
    $sth->execute($name);
    ($id) = $sth->fetchrow_array;
  }
  return {id => $id, client_id => $client_id, client_secret => $client_secret};
};

helper verify_client => sub {
  my $c = shift;
  my ($client_id, $client_secret) = @_;
  my $sth = eval { $c->db->prepare('SELECT 1 FROM clients WHERE client_id = ? AND client_secret = ?') } || $log->fatal("Cannot select client secret from database");
  $sth->execute($client_id, $client_secret);
  my ($exists) = $sth->fetchrow_array;
  return $exists;
};


# users
helper create_users_table => sub {
  my $c = shift;
  $c->db->do('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username, password, email, is_confirmed)');
};

app->create_users_table;

# https://perlmaven.com/storing-passwords-in-a-an-easy-but-secure-way
my $pbkdf2 = Crypt::PBKDF2->new(hash_class => 'HMACSHA2');

helper register_user => sub {
  my $c = shift;
  my ($username, $email, $password) = @_;
  # does the user already exist?
  my $sth = eval { $c->db->prepare('SELECT 1 FROM users WHERE username = ?') } || $log->fatal("Cannot select user from database");
  $sth->execute($username);
  my ($exists) = $sth->fetchrow_array;
  if ($exists) {
    $log->info("Attempting to register the existing name '$username'");
    $c->render(status => 500, text => 'User already exists');
    return 0;
  }
  my $hash = $pbkdf2->generate($password);
  $sth = eval { $dbh->prepare('INSERT INTO users (username, email, password, is_confirmed) VALUES (?, ?, ?, 0)') } || $log->fatal("Cannot insert user into database");
  $sth->execute($username, $email, $hash);
  return 1;
};

helper verify_user => sub {
  my $c = shift;
  my ($username, $password) = @_;
  # strange but true: we are getting the email address in the username param
  my $sth = eval { $c->db->prepare('SELECT password FROM users WHERE email = ?') } || $log->fatal("Cannot select user password from database");
  $sth->execute($username);
  my ($hash) = $sth->fetchrow_array;
  return $pbkdf2->validate($hash, $password);
};

helper get_user => sub {
  my $c = shift;
  my ($user_id) = @_; # the email address used as the user_id by oauth
  # id: The ID of the account
  # username: The username of the account
  # acct: Equals username for local users, includes @domain for remote ones
  # display_name: The account's display name
  # locked: Boolean for when the account cannot be followed without waiting for approval first
  # created_at: The time the account was created
  # followers_count: The number of followers for the account
  # following_count: The number of accounts the given account is following
  # statuses_count: The number of statuses the account has made
  # note: Biography of user
  # url: URL of the user's profile page (can be remote)
  # avatar: URL to the avatar image
  # avatar_static: URL to the avatar static image (gif)
  # header: URL to the header image
  # header_static: URL to the header static image (gif)
  my $sth = eval { $c->db->prepare('SELECT id, username FROM users WHERE email = ?') } || $log->fatal("Cannot select user from database");
  $sth->execute($user_id);
  my ($id, $username) = $sth->fetchrow_array;
  my $user = {};
  $user->{id} = $id;
  $user->{username} = $username if $username;
  return $user;
};

# tokens
helper create_tokens_table => sub {
  my $c = shift;
  $c->db->do('CREATE TABLE IF NOT EXISTS access_tokens (access_token, scope, expires, refresh_token, client_id INTEGER, user_id INTEGER)');
  $c->db->do('CREATE TABLE IF NOT EXISTS refresh_tokens (refresh_token, access_token, scope, client_id INTEGER, user_id INTEGER)');
};

app->create_tokens_table;

helper get_access_token => sub {
  my $c = shift;
  my ($token) = @_;
  my $sth = eval { $c->db->prepare('SELECT access_token, scope, expires, user_id FROM access_tokens WHERE access_token = ?') } || $log->fatal("Cannot select access_token from database");
  $sth->execute($token);
  my ($access_token, $scope, $expires, $user_id) = $sth->fetchrow_array;
  $scope = [split(/ /, $scope)] if $scope;
  return {access_token => $access_token, scope => $scope, expires => $expires, user_id => $user_id};
};

helper get_refresh_token => sub {
  my $c = shift;
  my ($token) = @_;
  my $sth = eval { $c->db->prepare('SELECT access_token, scope, user_id FROM refresh_tokens WHERE refresh_token = ?') } || $log->fatal("Cannot select refresh_token from database");
  $sth->execute($token);
  my ($access_token, $scope, $user_id) = $sth->fetchrow_array;
  $scope = $scope && [split(/ /, $scope)];
  return {access_token => $access_token, scope => $scope, user_id => $user_id};
};

helper remove_access_token => sub {
  my $c = shift;
  my ($access_token) = @_;
  my $sth = eval { $c->db->prepare('DELETE FROM access_tokens WHERE access_token = ?') } || $log->fatal("Cannot delete access_token from database");
  $sth->execute($access_token);
};

helper remove_refresh_token => sub {
  my $c = shift;
  my ($client_id, $user_id) = @_;
  my $sth = eval { $c->db->prepare('DELETE FROM refresh_tokens WHERE client_id = ? AND user_id = ?') } || $log->fatal("Cannot delete refresh_token from database");
  $sth->execute($client_id, $user_id);
};

helper add_access_token => sub {
  my $c = shift;
  my ($access_token, $scope, $expires, $refresh_token, $client_id, $user_id) = @_;
  my $sth = eval { $dbh->prepare('INSERT INTO access_tokens (access_token, scope, expires, refresh_token, client_id, user_id) VALUES (?, ?, ?, ?, ?, ?)') } || $log->fatal("Cannot insert access_token into database");
  $sth->execute($access_token, join(' ',@$scope), $expires, $refresh_token, $client_id, $user_id);
};

helper add_refresh_token => sub {
  my $c = shift;
  my ($refresh_token, $access_token, $scope, $client_id, $user_id) = @_;
  my $sth = eval { $dbh->prepare('INSERT INTO refresh_tokens (refresh_token, access_token, scope, client_id, user_id) VALUES (?, ?, ?, ?, ?)') } || $log->fatal("Cannot insert refresh_token into database");
  $sth->execute($refresh_token, $access_token, join(' ',@$scope), $client_id, $user_id);
};


# tokens
helper create_auth_codes_table => sub {
  my $c = shift;
  $c->db->do('CREATE TABLE IF NOT EXISTS auth_codes (auth_code, client_id INTEGER, user_id INTEGER, expires, redirect_uri, scope)');
};

app->create_auth_codes_table;

helper get_auth_code => sub {
  my $c = shift;
  my ($auth_code) = @_;
  my $sth = eval { $c->db->prepare('SELECT client_id, user_id, expires, redirect_uri, scope FROM auth_codes WHERE auth_code = ?') } || $log->fatal("Cannot select auth_code from database");
  $sth->execute($auth_code);
  my ($client_id, $user_id, $expires, $redirect_uri, $scope) = $sth->fetchrow_array;
  return {auth_code => $auth_code, client_id => $client_id, user_id => $user_id, expires => $expires, redirect_uri => $redirect_uri, scope => $scope};
};


# Code from Net::OAuth2::AuthorizationServer::Manual

my $resource_owner_confirm_scopes_sub = sub {#FIXME
  $log->debug('resource_owner_confirm_scopes_sub');
  my ( %args ) = @_;

  my ( $obj,$client_id,$scopes_ref,$redirect_uri,$response_type )
      = @args{ qw/ mojo_controller client_id scopes redirect_uri response_type / };

  my $error;
  my $is_allowed = $obj->flash( "oauth_${client_id}" );

  # if user hasn't yet allowed the client access, or if they denied
  # access last time, we check [again] with the user for access
  if ( ! $is_allowed ) {
    $obj->flash( client_id => $client_id );
    $obj->flash( scopes    => $scopes_ref );

    # we need to redirect back to the /oauth/authorize route after
    # confirm/deny by resource owner (with the original params)
    my $uri = join( '?',$obj->url_for('current'),$obj->url_with->query );
    $obj->flash( 'redirect_after_login' => $uri );
    $obj->redirect_to( '/oauth/confirm_scopes' );
  }

  return ( $is_allowed,$error,$scopes_ref );
};

my $resource_owner_logged_in_sub = sub {
  $log->debug('resource_owner_logged_in_sub');
  my (%args) = @_;
  my $c = $args{mojo_controller};
  if (!$c->session('logged_in')) {
    # we need to redirect back to the /oauth/authorize route after
    # login (with the original params)
    my $uri = join( '?', $c->url_for('current'), $c->url_with->query);
    $c->flash('redirect_after_login' => $uri);
    $c->redirect_to('/oauth/login');
    return 0;
  }
  return 1;
};

my $verify_client_sub = sub { #FIXME
  $log->debug('verify_client_sub');
  my ( %args ) = @_;
  
  my ( $obj,$client_id,$scopes_ref,$client_secret,$redirect_uri,$response_type )
      = @args{ qw/ mojo_controller client_id scopes client_secret redirect_uri response_type / };
  
  if (my $client = $obj->db->get_collection( 'clients' )->find_one({ client_id => $client_id })) {
    my $client_scopes = [];
    
    # Check scopes
    foreach my $scope ( @{ $scopes_ref // [] } ) {
      
      if ( ! exists( $client->{scopes}{$scope} ) ) {
	return ( 0,'invalid_scope' );
      } elsif ( $client->{scopes}{$scope} ) {
	push @{$client_scopes}, $scope;
      }
    }
    
    # Implicit Grant Checks
    if ( $response_type && $response_type eq 'token' ) {
      # If 'credentials' have been assigned Implicit Grant should be prevented, so check for secret
      return (0, 'unauthorized_grant') if $client->{'secret'};
      
      # Check redirect_uri
      return (0, 'access_denied') 
	  if $client->{'redirect_uri'} && (!$redirect_uri || $redirect_uri ne $client->{'redirect_uri'});
      
      # Credentials Grant Checks
      if ($client_secret && $client_secret ne $client->{'secret'}) {
	return (0, 'access_denied');
      }
      
      return ( 1, undef, $client_scopes );
    }
  }
    
  return ( 0,'unauthorized_client2' );
};

my $store_auth_code_sub = sub { #FIXME
  $log->debug('store_auth_code_sub');
  my ( %args ) = @_;

  my ( $obj,$auth_code,$client_id,$expires_in,$uri,$scopes_ref ) =
      @args{qw/ mojo_controller auth_code client_id expires_in redirect_uri scopes / };

  my $auth_codes = $obj->db->get_collection( 'auth_codes' );

  my $id = $auth_codes->insert({
    auth_code    => $auth_code,
    client_id    => $client_id,
    user_id      => $obj->session( 'user_id' ),
    expires      => time + $expires_in,
    redirect_uri => $uri,
    scope        => { map { $_ => 1 } @{ $scopes_ref // [] } },
			       });

  return;
};
  
my $verify_auth_code_sub = sub { #FIXME
  $log->debug('verify_auth_code_sub');
  my ( %args ) = @_;

  my ( $obj,$client_id,$client_secret,$auth_code,$uri )
      = @args{qw/ mojo_controller client_id client_secret auth_code redirect_uri / };

  my $auth_codes      = $obj->db->get_collection( 'auth_codes' );
  my $ac              = $auth_codes->find_one({
    client_id => $client_id,
    auth_code => $auth_code,
					      });

  my $client = $obj->db->get_collection( 'clients' )
      ->find_one({ client_id => $client_id });

  $client || return ( 0,'unauthorized_client1' );

  if (
    ! $ac
    or $ac->{verified}
    or ( $uri ne $ac->{redirect_uri} )
    or ( $ac->{expires} <= time )
    or ( $client_secret ne $client->{client_secret} )
      ) {

    if ( $ac->{verified} ) {
      # the auth code has been used before - we must revoke the auth code
      # and access tokens
      $auth_codes->remove({ auth_code => $auth_code });
      $obj->db->get_collection( 'access_tokens' )->remove({
	access_token => $ac->{access_token}
							  });
    }

    return ( 0,'invalid_grant' );
  }

  # scopes are those that were requested in the authorization request, not
  # those stored in the client (i.e. what the auth request restriced scopes
  # to and not everything the client is capable of)
  my $scope = $ac->{scope};

  $auth_codes->update( $ac,{ verified => 1 } );

  return ( $client_id,undef,$scope,$ac->{user_id} );
};

my $store_access_token_sub = sub {
  $log->debug('store_access_token_sub');
  my (%args) = @_;
  my ($c, $client, $auth_code, $access_token, $refresh_token, $expires_in, $scope, $old_refresh_token)
      = @args{qw/mojo_controller client_id auth_code access_token refresh_token expires_in scopes old_refresh_token/};
  my $user_id;
  if (!defined($auth_code) && $old_refresh_token) {
    # must have generated an access token via refresh token so revoke the old
    # access token and refresh token (also copy required data if missing)
    my $prev_rt = $c->get_refresh_token($old_refresh_token);
    my $prev_at = $c->get_access_token($prev_rt->{access_token});
    # access tokens can be revoked, whilst refresh tokens can remain so we
    # need to get the data from the refresh token as the access token may
    # no longer exist at the point that the refresh token is used
    $scope //= $prev_rt->{scope};
    $user_id = $prev_rt->{user_id};
    # need to revoke the access token
    $c->remove_access_token($prev_at->{access_token});
  } else {
    $user_id = $c->get_auth_code($auth_code)->{user_id};
  }
  # $client is now a client_id!
  if (ref($client)) {
    $scope  = $client->{scope};
    $client = $client->{client_id};
  }
  # if the client has an existing refresh token we need to revoke it
  $c->remove_refresh_token($client, $user_id);
  # add new tokens
  $c->add_access_token($access_token, $scope, time + $expires_in, $refresh_token, $client, $user_id);
  $c->add_refresh_token($refresh_token, $access_token, $scope, $client, $user_id);
  # FIXME: expire empty?
};

my $verify_access_token_sub = sub {
  $log->debug('verify_access_token_sub');
  my (%args) = @_;
  my ($c, $access_token, $scopes_ref, $is_refresh_token)
      = @args{qw/mojo_controller access_token scopes is_refresh_token/};
  my $rt = $c->get_refresh_token($access_token);
  if ($is_refresh_token && $rt) {
    if ($scopes_ref) {
      foreach my $scope (@{$scopes_ref // []}) {
	if (!exists($rt->{scope}{$scope}) or !$rt->{scope}{$scope}) {
	  return (0,'scope_mismatch');
	}
      }
    }
    # $rt contains client_id, user_id, etc
    return $rt;
  }
  elsif (my $at = $c->get_access_token($access_token)) {
    if ($at->{expires} <= time) {
      # need to revoke the access token
      $c->remove_access_token($access_token);
      return (0,'access_token_expired');
    } elsif ($scopes_ref) {
      foreach my $scope (@{$scopes_ref // []}) {
	if (!exists($at->{scope}{$scope}) or !$at->{scope}{$scope}) {
	  return (0,'scope_mismatch');
	}
      }
    }
    # $at contains client_id, user_id, etc
    return $at;
  }
  return (0,'invalid_token');
};

my $verify_user_password_sub = sub {
  $log->debug('verify_user_password_sub');
  my (%args) = @_;
  my ($c, $client_id, $client_secret, $username, $password, $scopes) =
      @args{qw/mojo_controller client_id client_secret username password scopes/};
  $c->verify_client($client_id, $client_secret) || return (0, 'unauthorized_client');
  $c->verify_user($username, $password) || return (0, 'unauthorized_user');
  return ($client_id, undef, $scopes, $username);
};

plugin 'OAuth2::Server' => {
  authorize_route              => '/oauth/authorize',
  access_token_route           => '/oauth/token',
  login_resource_owner_cb      => $resource_owner_logged_in_sub,
  confirm_by_resource_owner_cb => $resource_owner_confirm_scopes_sub,
  verify_client_cb             => $verify_client_sub,
  store_auth_code_cb           => $store_auth_code_sub,
  verify_auth_code_cb          => $verify_auth_code_sub,
  store_access_token_cb        => $store_access_token_sub,
  verify_access_token_cb       => $verify_access_token_sub,
  verify_user_password_cb      => $verify_user_password_sub,
};

get '/' => sub {
  my ($c) = @_;
  $c->render(text => "Gomphotherium is up");
};

# https://github.com/tootsuite/documentation/blob/master/Using-the-API/API.md#apps
post '/api/v1/apps' => sub {
  my ($c) = @_;
  my $name = $c->param('client_name');
  my $website = $c->param('website');
  my $data = $c->register_client($name, $website);
  $c->render(json => $data);
};

# FIXME: should verify email address
post '/auth' => sub {
  my ($c) = @_;
  # the typical web form uses 'user_account_attributes_username'
  my $username = $c->param('username');
  my $email = $c->param('email');
  my $password = $c->param('password');
  if ($c->register_user($username, $email, $password)) {
    $c->render(text => "OK");
  }
};

post '/oauth/token' => sub {
  my ($c) = @_;
  if ($c->oauth) {
    $c->render(text => "OK");
  } else {
    $c->render(status => 401, text => 'Access denied');
  }
};

get '/api/v1/accounts/verify_credentials' => sub {
  my ($c) = @_;
  if (my $oauth_details = $c->oauth) {
    $log->debug($oauth_details->{user_id} . " authenticated!");
    my $user = $c->get_user($oauth_details->{user_id});
    $c->render(json => {
      id => $user->{id},
      username => $user->{username}});
  } else {
    $c->render(status => 401, text => 'Access denied');
  }
};

app->start;
