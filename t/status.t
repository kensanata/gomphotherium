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

use Test::More;
use Test::Mojo;
use Mojo::JSON qw(decode_json);
use FindBin;
use strict;
use warnings;

open(my $fh, '<:encoding(UTF-8)', 'test_credentials.txt') or die "Can't load credentials: $!";
my ($client_id, $client_secret, $access_token) = split(/ /, <$fh>);
close($fh);

require "$FindBin::Bin/../gomphotherium.pl";

my $t = Test::Mojo->new;

$t->ua->on(start => sub {
  my ($ua, $tx) = @_;
  $tx->req->headers->authorization("Bearer $access_token");
});

$t->post_ok('/api/v1/statuses' => form => {
  status => 'This is a test.' })
    ->status_is(200)
    ->json_has('/id')
    ->json_has('/created_at')
    ->json_is('/content', 'This is a test.')
    ->json_has('/account')
    ->json_is('/account/id', 1)
    ->json_is('/account/username', 'alex');

done_testing();
