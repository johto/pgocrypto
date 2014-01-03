-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgocrypto" to load this file. \quit

CREATE FUNCTION pgo_encrypt(plaintext bytea, secretkey bytea) RETURNS bytea
LANGUAGE sql
AS $_$
SELECT
    iv || encrypt_iv($1, $2, iv, 'aes-cbc/pad:pkcs')
FROM
(
    SELECT
        gen_random_bytes(16) AS iv
    OFFSET 0
) ss(iv)
$_$;

CREATE FUNCTION pgo_encrypt_string(plaintext text, secretkey bytea) RETURNS text
LANGUAGE sql
AS $_$
SELECT
    encode(iv || encrypt_iv(convert_to($1, 'UTF8'), $2, iv, 'aes-cbc/pad:pkcs'), 'base64')
FROM
(
    SELECT
        gen_random_bytes(16) AS iv
    OFFSET 0
) ss(iv)
$_$;

CREATE FUNCTION pgo_decrypt(ciphertext bytea, secretkey bytea) RETURNS bytea
LANGUAGE sql
AS $_$
SELECT decrypt_iv(data, $2, iv, 'aes-cbc/pad:pkcs')
FROM
(
    SELECT
        substring($1, 1, 16) AS iv,
        substring($1, 17) AS data
) ss
$_$;

CREATE FUNCTION pgo_decrypt_string(ciphertext text, secretkey bytea) RETURNS text
LANGUAGE sql
AS $_$
SELECT convert_from(decrypt_iv(data, $2, iv, 'aes-cbc/pad:pkcs'), 'UTF8')
FROM
(
    SELECT
        substring(ciphertext, 1, 16) AS iv,
        substring(ciphertext, 17) AS data
    FROM
    (
        VALUES (decode($1, 'base64'))
    ) ss(ciphertext)
) ss
$_$;

