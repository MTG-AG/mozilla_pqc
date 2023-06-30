//
// Created by sdeligeorgopoulos on 04.12.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_CMSRECINFO_H
#define MOZILLA_PROJECTS_MTG_CMSRECINFO_H

#define MTG_LIST_ENC_KEY_OIDS()\
        case SEC_OID_CME_KEY:

#define MTG_HANDLE_SMIME_ENC() \
        case SEC_OID_CME_KEY: \
                /* wrap the symkey */ \
                if (cert) { \
                        rv = mtg_CMSUtil_EncryptSymKey_CME(poolp, cert, bulkkey, ri->cmsg->contentInfo.content.envelopedData->contentInfo.keysize, &ri->ri.keyTransRecipientInfo.encKey); \
                        if (rv != SECSuccess)\
                        break;\
                } else if (usesSubjKeyID) {\
                        PORT_Assert(extra != NULL);\
                        rv = mtg_CMSUtil_EncryptSymKey_CMEPubKey(poolp, extra->pubKey, bulkkey, ri->cmsg->contentInfo.content.envelopedData->contentInfo.keysize, &ri->ri.keyTransRecipientInfo.encKey);\
                        if (rv != SECSuccess)\
                        break;\
                }\
                rv = SECOID_SetAlgorithmID(poolp, &(ri->ri.keyTransRecipientInfo.keyEncAlg), certalgtag, NULL);\
                break;

#define MTG_HANDLE_SMIME_DEC() \
        case SEC_OID_CME_KEY: \
                /* RSA encryption algorithm: */ \
                /* get the symmetric (bulk) key by unwrapping it using our private key */ \
                bulkkey = mtg_CMSUtil_DecryptSymKey_CME(privkey, enckey, bulkalgtag); \
                break;

SECStatus
mtg_CMSUtil_EncryptSymKey_CME(PLArenaPool *poolp, CERTCertificate *cert, PK11SymKey *bulkkey, int bulkKeyBitsSize,
                              SECItem *encKey);

SECStatus
mtg_CMSUtil_EncryptSymKey_CMEPubKey(PLArenaPool *poolp, SECKEYPublicKey *publickey, PK11SymKey *bulkkey,
                                    int bulkKeyBitsSize, SECItem *encKey);

PK11SymKey *
mtg_CMSUtil_DecryptSymKey_CME(SECKEYPrivateKey *privkey, SECItem *encKey, SECOidTag bulkalgtag);

#endif //MOZILLA_PROJECTS_MTG_CMSRECINFO_H
