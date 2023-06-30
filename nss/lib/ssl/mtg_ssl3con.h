//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MTG_SSL3CON_H
#define MTG_SSL3CON_H

#define MTG_MAX_HANDSHAKE_MSG_LEN 0xffE0000

/**
 * MTG PQC cipher suites
 * used in ssl3con.c:88, static ssl3CipherSuiteCfg cipherSuites[ssl_V3_SUITES_IMPLEMENTED]
 */
#define MTG_GET_CIPHER_SUITES() \
{ TLS_CME_SPX_WITH_AES_256_GCM_SHA256 , SSL_ALLOWED, PR_TRUE, PR_FALSE },\
{ TLS_CMEE_SPX_WITH_AES_256_GCM_SHA256 , SSL_ALLOWED, PR_TRUE, PR_FALSE }


/**
 * used in ssl3con.c:190, static const SSLSignatureScheme defaultSignatureSchemes[]
 */
#define MTG_GET_SIGNATURES() \
    ssl_sig_spx_sha512

/**
 * used in ssl3con.c:232, static const PRUint8 certificate_types[]
 */
#define MTG_GET_CERT_TYPES() \
    ct_SPX_sign,\
    ct_SPX_fixed_CME


/**
 * used in ssl3con.c:232, static const ssl3KEADef kea_defs[]
 */
#define MTG_GET_KEA_DEFS() \
    { kea_cme_spx, ssl_kea_cme, nullKey, ssl_auth_cme, PR_FALSE, SEC_OID_TLS_CME_SPX },\
    { kea_cmee_spx, ssl_kea_cme, spxKey, ssl_auth_spx, PR_TRUE, SEC_OID_TLS_CMEE_SPX }


/**
* used in ssl3con.c:232, static const ssl3CipherSuiteDef cipher_suite_defs[]
*/
#define MTG_GET_CIPHER_SUITES_DEFS() \
    { TLS_CME_SPX_WITH_AES_256_GCM_SHA256, cipher_aes_256_gcm, ssl_mac_aead, kea_cme_spx, ssl_hash_sha256 },\
    { TLS_CMEE_SPX_WITH_AES_256_GCM_SHA256, cipher_aes_256_gcm, ssl_mac_aead, kea_cmee_spx, ssl_hash_sha256 }


/**
* used in ssl3con.c:232, static const CK_MECHANISM_TYPE auth_alg_defs[]
*/
#define MTG_GET_ATH_ALG_DEFS() \
    CKM_SHA512_SPX,       /* ssl_auth_spx */ \
    CKM_CME_WRAP               /* ssl_auth_cme */


/**
* used in ssl3con.c:232, static const CK_MECHANISM_TYPE kea_alg_defs[]
*/
#define MTG_GET_KEA_ALG_DEFS() \
    CKM_CME_WRAP               /* ssl_kea_cme */

/**
 * used in ssl3con.c:232, static PRBool ssl3_CipherSuiteAllowedForVersionRange(ssl3CipherSuite cipherSuite, const SSLVersionRange *vrange)
 */
#define MTG_GET_CIPHER_SUITES_TLS_VERSION_REQ(vrange) \
    case TLS_CME_SPX_WITH_AES_256_GCM_SHA256: \
    case TLS_CMEE_SPX_WITH_AES_256_GCM_SHA256: \
        return vrange->max >= SSL_LIBRARY_VERSION_TLS_1_2 && \
                vrange->min < SSL_LIBRARY_VERSION_TLS_1_3;

/**
* used in ssl3con.c:232, static PRBool ssl_KEAEnabled(const sslSocket *ss, SSLKEAType keaType)
*/
#define MTG_GET_KEA_ENABLED(ss, keaType) \
    case ssl_kea_cme:\
        return PR_TRUE;

// TODO
/**
* used in ssl3con.c:232, static PRBool ssl_HasCert(const sslSocket *ss, SSLAuthType authType)
*/
#define MTG_GET_HAS_CERT(ss, authType) \
    if (authType == ssl_auth_spx) { \
        /* add checks for appropriate certificate */\
        return PR_TRUE;\
    }\
    if (authType == ssl_auth_cme) {\
        /* add checks for appropriate certificate */\
        return PR_TRUE;\
    }


/**
* used in ssl3con.c:232, static SECStatus ssl3_SendClientKeyExchange(sslSocket *ss)
*/
#define MTG_SEND_CLIENT_KEY_EXCHANGE(ss, serverKey) \
    case ssl_kea_cme: \
        rv = ssl3_SendCMEClientKeyExchange(ss, serverKey); \
        break;

#define MTG_CERT_VALIDATION()


/**
* used in ssl3con.c:232, SECStatus ssl3_AuthCertificate(sslSocket *ss)
*/
#define MTG_GET_MIN_PUB_KEY_LEN() \
    case spxKey:\
    case cmeKey:\
        rv = SECSuccess;\
        minKey = 256;\
        break;

/**
* used in ssl3con.c:232, static SECStatus ssl3_HandleServerKeyExchange(sslSocket *ss, PRUint8 *b, PRUint32 length)
*/
#define MTG_HANDLE_SERVER_KEY_EXCHANGE(ss, b, length) \
    case ssl_kea_cme:\
        rv = ssl3_HandleCMEServerKeyExchange(ss, b, length);\
        break;
    
/**
 * used in ssl3_ComputeMasterSecretInt and tls_ComputeExtendedMasterSecretInt to mask the mtg kea as dh and allow the use
 * of CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH instead of CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE.
 * here the newer CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE requires a fixed 48 Bytes PMS, see: pkcs11c.c: 6729
 * on the other side, CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH allows arbitary(32) PMS lengths
 */
#define MTG_SET_KEA_AS_DH(exchKeyType)\
    switch(exchKeyType)\
    {\
        case ssl_kea_cme: \
            isDH = PR_TRUE;\
            break;\
        default:\
            break;\
    }

#define MTG_GET_HASH_FOR_SIG()\
    case ssl_sig_spx_sha512:\
        return ssl_hash_sha512;

#define MTG_GET_OID_FOR_SIG()\
    case ssl_sig_spx_sha512:\
        return spkiOid == SEC_OID_SPX_KEY;

#define MTG_LIST_SIG_KEYS()\
    case ssl_sig_spx_sha512:

#define MTG_GET_KEY_TYPE_FOR_SIG_OID()\
    case SEC_OID_SPX_KEY:\
        return keaDef->signKeyType == spxKey;

#define MTG_GET_AUTH_FOR_SIG()\
    case ssl_sig_spx_sha512:\
        return ssl_auth_spx;

#define MTG_GET_OID_FOR_KEY_TYPE()\
    case spxKey:\
        if (scheme != ssl_sig_spx_sha512) {\
            PORT_SetError(SEC_ERROR_UNSUPPORTED_KEYALG);\
            goto loser;\
        }\
        encAlg = SEC_OID_SPX_SHA512_SIGNATURE;\
        if (hash->hashAlg == ssl_hash_none) {\
            hashAlg = SEC_OID_SHA1;\
            hashItem.data = hash->u.s.sha;\
            hashItem.len = sizeof(hash->u.s.sha);\
        } else {\
            hashItem.data = hash->u.raw;\
            hashItem.len = hash->len;\
        }\
        break;

PK11SymKey *ssl3_GenerateCMEPMS(sslSocket *ss, ssl3CipherSpec *spec,
                    PK11SlotInfo *serverKeySlot);

#define MTG_GenerateCMEPMS() \
   PK11SymKey *ssl3_GenerateCMEPMS(sslSocket *ss, ssl3CipherSpec *spec, PK11SlotInfo *serverKeySlot)\
   {\
     return ssl3_GenerateRSAPMS(ss, spec, serverKeySlot); \
   }

SECStatus
ssl3_HandleNHServerKeyExchange(sslSocket *ss, PRUint8 *b, PRUint32 length);

SECStatus
ssl3_HandleCMEServerKeyExchange(sslSocket *ss, PRUint8 *b, PRUint32 length);

#endif //MTG_SSL3CON_H
