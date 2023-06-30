//
// Created by sdeligeorgopoulos on 05.11.2018.
//
#include "pk11pub.h"
#include "sslimpl.h"
#include "sslproto.h"

#include "mtg_ssl3con.h"

/* Caller must set hiLevel error code. */
/* Called from ssl3_HandleServerKeyExchange. */
static SECStatus
ssl3_ComputeMtgKeyHash(sslSocket *ss, SSLHashType hashAlg, SSL3Hashes *hashes,
                       SECItem server_bytes)
{
    sslBuffer buf = SSL_BUFFER_EMPTY;
    SECStatus rv;

            PORT_Assert(server_bytes.data);

    rv = sslBuffer_Append(&buf, ss->ssl3.hs.client_random, SSL3_RANDOM_LENGTH);
    if (rv != SECSuccess) {
        goto loser;
    }
    rv = sslBuffer_Append(&buf, ss->ssl3.hs.server_random, SSL3_RANDOM_LENGTH);
    if (rv != SECSuccess) {
        goto loser;
    }
    /* server_bytes */
    rv = sslBuffer_Append(&buf, server_bytes.data, server_bytes.len);
    if (rv != SECSuccess) {
        goto loser;
    }

    rv = ssl3_ComputeCommonKeyHash(hashAlg, SSL_BUFFER_BASE(&buf),
                                   SSL_BUFFER_LEN(&buf), hashes);
    if (rv != SECSuccess) {
        goto loser;
    }

    PRINT_BUF(95, (NULL, "MTGkey hash: ", SSL_BUFFER_BASE(&buf),
            SSL_BUFFER_LEN(&buf)));
    if (hashAlg == ssl_hash_none) {
        PRINT_BUF(95, (NULL, "MTGkey hash: MD5 result",
                hashes->u.s.md5, MD5_LENGTH));
        PRINT_BUF(95, (NULL, "MTGkey hash: SHA1 result",
                hashes->u.s.sha, SHA1_LENGTH));
    } else {
        PRINT_BUF(95, (NULL, "MTGkey hash: result",
                hashes->u.raw, hashes->len));
    }

    sslBuffer_Clear(&buf);
    return SECSuccess;

    loser:
    sslBuffer_Clear(&buf);
    return SECFailure;
}

SECStatus
ssl3_HandleCMEServerKeyExchange(sslSocket *ss, PRUint8 *b, PRUint32 length)
{
    SECStatus rv;
    int errCode = SSL_ERROR_RX_MALFORMED_SERVER_KEY_EXCH;
    SSL3AlertDescription desc = illegal_parameter;
    SSLHashType hashAlg;
    PRBool isTLS = ss->ssl3.prSpec->version > SSL_LIBRARY_VERSION_3_0;
    SSLSignatureScheme sigScheme;
    SECItem cme_key = { siBuffer, NULL, 0 };
    SSL3Hashes hashes;
    SECItem signature = { siBuffer, NULL, 0 };
    SECKEYPublicKey *peerKey = NULL;

    rv = ssl3_ConsumeHandshakeVariable(ss, &cme_key, 3, &b, &length);
    if (rv != SECSuccess) {
        goto loser; /* malformed. */
    }

    if (ss->version >= SSL_LIBRARY_VERSION_TLS_1_2) {
        rv = ssl_ConsumeSignatureScheme(ss, &b, &length, &sigScheme);
        if (rv != SECSuccess) {
            goto loser; /* malformed or unsupported. */
        }
        rv = ssl_CheckSignatureSchemeConsistency(ss, sigScheme,
                                                 ss->sec.peerCert);
        if (rv != SECSuccess) {
            goto loser;
        }
        hashAlg = ssl_SignatureSchemeToHashType(sigScheme);
    } else {
        /* Use ssl_hash_none to represent the MD5+SHA1 combo. */
        hashAlg = ssl_hash_none;
        sigScheme = ssl_sig_none;
    }
    rv = ssl3_ConsumeHandshakeVariable(ss, &signature, 2, &b, &length);
    if (rv != SECSuccess) {
        goto loser; /* malformed. */
    }
    if (length != 0) {
        if (isTLS) {
            desc = decode_error;
        }
        goto alert_loser; /* malformed. */
    }

    /* failures after this point are not malformed handshakes. */
    /* TLS: send decrypt_error if signature failed. */
    desc = isTLS ? decrypt_error : handshake_failure;

    /*
     * Check to make sure the hash is signed by right guy.
     */
    rv = ssl3_ComputeMtgKeyHash(ss, hashAlg, &hashes, cme_key);
    if (rv != SECSuccess) {
        errCode =
                ssl_MapLowLevelError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
        goto alert_loser;
    }

    rv = ssl3_VerifySignedHashes(ss, sigScheme, &hashes, &signature);
    if (rv != SECSuccess) {
        errCode =
                ssl_MapLowLevelError(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE);
        goto alert_loser;
    }

    /*
     * we really need to build a new key here because we can no longer
     * ignore calling SECKEY_DestroyPublicKey. Using the key may allocate
     * pkcs11 slots and ID's.
     */
    peerKey = SECKEY_ImportDERPublicKey(&cme_key, CKK_CME);

    if (peerKey == NULL) {
        errCode = SEC_ERROR_NO_MEMORY;
        goto loser;
    }

    ss->sec.peerKey = peerKey;
    return SECSuccess;

    alert_loser:
    (void)SSL3_SendAlert(ss, alert_fatal, desc);
    loser:
    PORT_SetError(ssl_MapLowLevelError(errCode));
    return SECFailure;
}

/* Called from ssl3_SendClientKeyExchange(). */
SECStatus
ssl3_SendCMEClientKeyExchange(sslSocket *ss, SECKEYPublicKey *svrPubKey)
{
    PK11SymKey *pms = NULL;
    SECItem enc_pms = { siBuffer, NULL, 0 };
    SECStatus rv = SECFailure;
    PRBool isTLS;

    if (svrPubKey->keyType != cmeKey) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        goto loser;
    }

    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveXmitBufLock(ss));

    /* Generate the pre-master secret ...  */
    ssl_GetSpecWriteLock(ss);
    isTLS = (PRBool)(ss->version > SSL_LIBRARY_VERSION_3_0);

    pms = ssl3_GenerateCMEPMS(ss, ss->ssl3.pwSpec, NULL);
    ssl_ReleaseSpecWriteLock(ss);
    if (pms == NULL) {
        ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
        goto loser;
    }

    /* Get the wrapped (encrypted) pre-master secret, enc_pms */
    unsigned int svrPubKeyBits = SECKEY_PublicKeyStrengthInBits(svrPubKey);
    enc_pms.len = (svrPubKeyBits + 7) / 8 + 48;
    /* Check that the RSA key isn't larger than 8k bit. */
    if (svrPubKeyBits > SSL_MAX_RSA_KEY_BITS) {
        (void)SSL3_SendAlert(ss, alert_fatal, illegal_parameter);
        ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
        goto loser;
    }
    enc_pms.data = (unsigned char *)PORT_Alloc(enc_pms.len);
    if (enc_pms.data == NULL) {
        goto loser; /* err set by PORT_Alloc */
    }

    /* Wrap pre-master secret in server's public key. */
    rv = PK11_PubWrapSymKey(CKM_CME_WRAP, svrPubKey, pms, &enc_pms);
    if (rv != SECSuccess) {
        ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
        goto loser;
    }

    rv = ssl3_AppendHandshakeHeader(ss, ssl_hs_client_key_exchange,
                                    isTLS ? enc_pms.len + 2
                                          : enc_pms.len);
    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }
    if (isTLS) {
        rv = ssl3_AppendHandshakeVariable(ss, enc_pms.data, enc_pms.len, 2);
    } else {
        rv = ssl3_AppendHandshake(ss, enc_pms.data, enc_pms.len);
    }
    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }

    rv = ssl3_InitPendingCipherSpecs(ss, pms, PR_TRUE);
    PK11_FreeSymKey(pms);
    pms = NULL;

    if (rv != SECSuccess) {
        ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
        goto loser;
    }

    rv = SECSuccess;

    loser:
    if (enc_pms.data != NULL) {
        PORT_Free(enc_pms.data);
    }
    if (pms != NULL) {
        PK11_FreeSymKey(pms);
    }
    return rv;
}

/* Called from ssl3_SendClientKeyExchange(). */
SECStatus
ssl3_SendNHClientKeyExchange(sslSocket *ss, SECKEYPublicKey *svrPubKey)
{
    PK11SymKey *pms = NULL;
    SECStatus rv = SECFailure;
    PRBool isTLS, isTLS12;
    CK_MECHANISM_TYPE target;
    const sslNamedGroupDef *groupDef;
    sslEphemeralKeyPair *keyPair = NULL;
    SECKEYPublicKey *pubKey;

            PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));
            PORT_Assert(ss->opt.noLocks || ssl_HaveXmitBufLock(ss));

    isTLS = (PRBool)(ss->version > SSL_LIBRARY_VERSION_3_0);
    isTLS12 = (PRBool)(ss->version >= SSL_LIBRARY_VERSION_TLS_1_2);

    /* Generate ephemeral EC keypair */
    if (svrPubKey->keyType != ecKey) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        goto loser;
    }
    groupDef = ssl_ECPubKey2NamedGroup(svrPubKey);
    if (!groupDef) {
        PORT_SetError(SEC_ERROR_BAD_KEY);
        goto loser;
    }
    ss->sec.keaGroup = groupDef;
    rv = ssl_CreateECDHEphemeralKeyPair(ss, groupDef, &keyPair);
    if (rv != SECSuccess) {
        ssl_MapLowLevelError(SEC_ERROR_KEYGEN_FAIL);
        goto loser;
    }

    pubKey = keyPair->keys->pubKey;
    PRINT_BUF(50, (ss, "ECDH public value:",
            pubKey->u.ec.publicValue.data,
            pubKey->u.ec.publicValue.len));

    if (isTLS12) {
        target = CKM_TLS12_MASTER_KEY_DERIVE_DH;
    } else if (isTLS) {
        target = CKM_TLS_MASTER_KEY_DERIVE_DH;
    } else {
        target = CKM_SSL3_MASTER_KEY_DERIVE_DH;
    }

    /* Determine the PMS */
    pms = PK11_PubDeriveWithKDF(keyPair->keys->privKey, svrPubKey,
                                PR_FALSE, NULL, NULL, CKM_ECDH1_DERIVE, target,
                                CKA_DERIVE, 0, CKD_NULL, NULL, NULL);

    if (pms == NULL) {
        (void)SSL3_SendAlert(ss, alert_fatal, illegal_parameter);
        ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
        goto loser;
    }

    rv = ssl3_AppendHandshakeHeader(ss, ssl_hs_client_key_exchange,
                                    pubKey->u.ec.publicValue.len + 1);
    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }

    rv = ssl3_AppendHandshakeVariable(ss, pubKey->u.ec.publicValue.data,
                                      pubKey->u.ec.publicValue.len, 1);

    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }

    rv = ssl3_InitPendingCipherSpecs(ss, pms, PR_TRUE);
    if (rv != SECSuccess) {
        ssl_MapLowLevelError(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE);
        goto loser;
    }

    PK11_FreeSymKey(pms);
    ssl_FreeEphemeralKeyPair(keyPair);
    return SECSuccess;

    loser:
    if (pms)
        PK11_FreeSymKey(pms);
    if (keyPair)
        ssl_FreeEphemeralKeyPair(keyPair);
    return SECFailure;
}