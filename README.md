Allow to communicate with local authority API.
Examples:
- Get X.509 authorities
```
go run main.go -action XP
```

- Prepare a new X.509 authority
```
go run main.go -action XP
```

- Activate a prepared X.509 authority
```
go run main.go -action XA -id SOME_ID
```

- Taint an old X.509 authority
```
go run main.go -action XT -id SOME_ID
```

- Revoke a tainted X.509 authority
```
go run main.go -action XR -id SOME_ID
```

- Taint an X.509 upstream authority
```
go run main.go -action XUR -id SOME_SKID
```

- Get JWT authority
```
go run main.go -action JP
```
- Prepare a new JWT authority
```
go run main.go -action JP
```
...
