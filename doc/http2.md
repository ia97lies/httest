# HTTP/2
Integrate http/2 to httest. Supporting as many stuff as possible.

## Syntax
### Proposal 1
http/2 is able to handle many requests on one connection, so we need some kind
of a body doing so.

CLIENT
	_REQ localhost SSL:8080
	_H2:BEGIN 
		__GET / HTTP/2.0
		__Host: localhost:8080
		__
		_EXPECT . "Hello"
		_WAIT

		__GET /foo/bar HTTP/2.0
		__Host: localhost:8080
		__
		_EXPECT . "World"
		_WAIT
	_H2:END
END

SERVER SSL:8080
	RES
	H2:BEGIN
		_WAIT
		__HTTP/2.0 OK
		__Content-Length:AUTO
		__
		__Hello

		_WAIT
		__HTTP/2.0 OK
		__Content-Length:AUTO
		__
		__World
	H2:END
END

That should be send on two channels in http/2 in a concurrent mode.
The big problem will be to schedule the request in a predictable way on the
server.

### Proposal 2
CLIENT
    _REQ localhost SSL:8080
	_EXPECT . "PUSH_PROMISE"
	_H2:SETTINGS <some settings parameter>
	_EXPECT . "PING"
	_H2:PING hello world
END

SERVER SSL:8080
	_RES
	_H2:SETTINGS <some settings parameter>
END
