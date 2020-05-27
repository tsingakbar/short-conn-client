# short-conn-client

http client library imlemented with short connection.

copy short-conn-client.h/cc to your project and your are ready to go.

## why this project: **accurate async timeout**

I need to access another http micro-service but lacking good enough c++ async http client library to use.

We used to use https://github.com/TarsCloud/TarsCpp/blob/master/util/include/util/tc_http_async.h for this
purpose, but the timeout implementation in it is far from accurate: say 5ms timeout but it actually can 
take much more than 5ms to trigger callback, which is not acceptable in my case.

## production prooved

The internet service using this library to access another http miroc-service handles 3,000,000,000 requests 
daily with accurate timeout triggering.
