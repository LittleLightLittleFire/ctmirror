ctmirror
========

Scans the certificate transparency log and stores the `Subject`, `Issuer`, `[]DNSName` of each certificate into a SQL database.

## Set up ##

1. Install [goose](https://bitbucket.org/liamstask/goose/)
3. Edit `db/dbconf.yml`, a sample file is provided
2. `goose up`

## Running ##

    go build
    ./ctmirror

Each time you run it will update from the last fetched index.
