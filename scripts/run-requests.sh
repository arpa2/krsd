#!/bin/bash

## run various requests against running test server.
## this script is pretty useless on it's own, but used by leakcheck.sh/limitcheck.sh

get() {
  echo -n "GET $1"
  curl -H "Authorization: Bearer static-token-for-now" $1 >/dev/null 2>&1
  echo " -> $?"
}

put() {
  echo -n "PUT $1"
  curl -X PUT -H "Authorization: Bearer static-token-for-now" $1 --data "$2" >/dev/null 2>&1
  echo " -> $?"
}

delete() {
  echo -n "DELETE $1"
  curl -X DELETE -H "Authorization: Bearer static-token-for-now" $1 --data "$2" >/dev/null 2>&1
  echo " -> $?"
}

# webfinger requests
get http://localhost:8181/.well-known/webfinger
get http://localhost:8181/.well-known/webfinger?resource=acct%3Ame@local.dev
# valid authorization requests
get 'http://localhost:8181/auth?redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fsome%2Fapp&scope=:rw'
get 'http://localhost:8181/auth?redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fsome%2Fapp&scope=contacts:rw'
get 'http://localhost:8181/auth?redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fsome%2Fapp&scope=contacts:rw%20calendar:r'
# authorization request w/o redirect_uri
get http://localhost:8181/auth?scope=contacts:rw
# authorization request w/o scope
get http://localhost:8181/auth?redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fsome%2Fapp
# authorization request w/o any params
get http://localhost:8181/auth?
# authorization request w/o query
get http://localhost:8181/auth
# retrieve some directories
get http://localhost:8181/storage/ 
get http://localhost:8181/storage/src/
get http://localhost:8181/storage/scripts/
# retrieve some files
get http://localhost:8181/storage/Makefile
get http://localhost:8181/storage/rs-serve
get http://localhost:8181/storage/LICENSE
get http://localhost:8181/storage/src/main.c
get http://localhost:8181/storage/src/config.h
get http://localhost:8181/storage/src/rs-serve.h
get http://localhost:8181/storage/src/storage.c
# create some stuff
put http://localhost:8181/storage/foo/bar/a "File A"
put http://localhost:8181/storage/foo/bar/b "File B"
put http://localhost:8181/storage/foo/bar/c "File C"
put http://localhost:8181/storage/foo/bar/baz/d "File D"
put http://localhost:8181/storage/foo/bar/baz/e "File E"
put http://localhost:8181/storage/foo/bar/baz/f "File F"
# retrieve just created files & folders
get http://localhost:8181/storage/foo/
get http://localhost:8181/storage/foo/bar/
get http://localhost:8181/storage/foo/bar/a
get http://localhost:8181/storage/foo/bar/b
get http://localhost:8181/storage/foo/bar/c
get http://localhost:8181/storage/foo/bar/baz/
get http://localhost:8181/storage/foo/bar/baz/d
get http://localhost:8181/storage/foo/bar/baz/e
get http://localhost:8181/storage/foo/bar/baz/f
# delete some files
delete http://localhost:8181/storage/foo/bar/a
delete http://localhost:8181/storage/foo/bar/b
delete http://localhost:8181/storage/foo/bar/c
# attempt to get deleted files & dir
get http://localhost:8181/storage/foo/bar/
get http://localhost:8181/storage/foo/bar/a
get http://localhost:8181/storage/foo/bar/b
get http://localhost:8181/storage/foo/bar/c
# delete the rest
delete http://localhost:8181/storage/foo/bar/baz/d
delete http://localhost:8181/storage/foo/bar/baz/e
delete http://localhost:8181/storage/foo/bar/baz/f

