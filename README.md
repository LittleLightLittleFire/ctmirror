ctmirror
========

Scans the certificate transparency log and stores the `Subject`, `Issuer`, `[]DNSName` of each certificate into a set of csv files.

## Running ##

    go build
    ./ctmirror

It currently does not store the starting index, you'll need to pass it in yourself via the arguments. ~9 hours to sync on a domestic connection.
