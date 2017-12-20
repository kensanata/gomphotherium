# Gomphotherium

"Gomphotherium is an extinct genus of proboscid that evolved in the
Early Miocene of North America and lived for about 12.4 million years"
– [Wikipedia](https://en.wikipedia.org/wiki/Gomphotherium)

One day this will be
a [Mastodon](https://github.com/tootsuite/mastodon#mastodon) server
written in Perl using [Mojolicious](http://mojolicious.org/).

## Development

Run the tests to get a hang of what the application can do.

```
prove t
```

This will generate a file called `test_credentials.txt` which you can
use. It contains three parameters: `client_id`, `client_secret` and
`access_token`. The access token is useful to run further tests from
the command line.

First, start the server.

```
morbo gomphotherium.pl
```

Copy the access token from the file with the test credentials and
prepare a command like the following, replacing `TOKEN` with the
access token (something like
`MTUxMzc3NjQxMy02NjM5NzUtMC4yODE3OTA4ODc2OTUzOTctaUxlMllTRkFEOW1ld2gyYlVQeGZHRkRYaFFoWUFX`
or the like).

```
curl --header "Authorization: Bearer TOKEN" -sS http://localhost:3000/api/v1/accounts/verify_credentials
```

The expected output:

```
{"id":1,"username":"alex"}
```

