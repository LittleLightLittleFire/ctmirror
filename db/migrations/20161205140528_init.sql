-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Entries of the CT tree
CREATE TABLE entries (
     -- ID of the entry in the CT tree
    id                   bigint    PRIMARY KEY,

    -- CommonName of the issuer
    issuer               text      NOT NULL,
    issuer_organisation  text      NOT NULL,

    -- Subject of the certificate
    subject              text      NOT NULL,
    subject_organisation text      NOT NULL,

    -- Validitiy
    not_before           timestamp NOT NULL,
    not_after            timestamp NOT NULL
);

-- Each certificate can specify an array of DNSNames
CREATE TABLE dnsnames (
    id      bigserial PRIMARY KEY,

    -- The certificate being referenced
    entry   bigint    NOT NULL REFERENCES Entries(id),

    -- The DNSName included in the certificate
    dnsname text      NOT NULL
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE IF EXISTS dnsnames;
DROP TABLE IF EXISTS entries;

