//
// Created by sdeligeorgopoulos on 04.12.2018.
//

#include "cert.h"
#include "keyhi.h"
#include "secasn1.h"
#include "secitem.h"
#include "secoid.h"
#include "pk11func.h"
#include "secerr.h"

#include "mtg_cmsrecinfo.h"

/* ====== CME ======================================================================= */

/*
 * mtg_CMSUtil_EncryptSymKey_CME - wrap a symmetric key with CME
 *
 * this function takes a symmetric key and encrypts it using an CME public key
 * according to me :) (S/MIME)
 */
SECStatus
mtg_CMSUtil_EncryptSymKey_CME(PLArenaPool *poolp, CERTCertificate *cert,
                              PK11SymKey *bulkkey, int bulkKeyBitsSize,
                              SECItem *encKey)
{
    SECStatus rv;
    SECKEYPublicKey *publickey;

    publickey = CERT_ExtractPublicKey(cert);
    if (publickey == NULL)
        return SECFailure;

    rv = mtg_CMSUtil_EncryptSymKey_CMEPubKey(poolp, publickey, bulkkey, bulkKeyBitsSize, encKey);
    SECKEY_DestroyPublicKey(publickey);
    return rv;
}

SECStatus
mtg_CMSUtil_EncryptSymKey_CMEPubKey(PLArenaPool *poolp,
                                    SECKEYPublicKey *publickey,
                                    PK11SymKey *bulkkey, int bulkKeyBitsSize, SECItem *encKey)
{
    SECStatus rv;
    unsigned int data_len;
    KeyType keyType;
    void *mark = NULL;

    mark = PORT_ArenaMark(poolp);
    if (!mark)
        goto loser;

    /* sanity check */
    keyType = SECKEY_GetPublicKeyType(publickey);
    PORT_Assert(keyType == cmeKey);
    if (keyType != cmeKey)
    {
        goto loser;
    }
    /* allocate memory for the encrypted key */
    data_len = SECKEY_PublicKeyStrength(publickey) + (bulkKeyBitsSize + 7) / 8;
    encKey->data = (unsigned char *) PORT_ArenaAlloc(poolp, data_len);
    encKey->len = data_len;
    if (encKey->data == NULL)
        goto loser;

    /* encrypt the key now */
    rv = PK11_PubWrapSymKey(CKM_CME_WRAP, publickey, bulkkey, encKey);

    if (rv != SECSuccess)
        goto loser;

    PORT_ArenaUnmark(poolp, mark);
    return SECSuccess;

    loser:
    if (mark)
    {
        PORT_ArenaRelease(poolp, mark);
    }
    return SECFailure;
}

/*
 * mtg_CMSUtil_DecryptSymKey_CME - unwrap a CME-wrapped symmetric key
 *
 * this function takes an CME-wrapped symmetric key and unwraps it, returning a symmetric
 * key handle. Please note that the actual unwrapped key data may not be allowed to leave
 * a hardware token...
 */
PK11SymKey *
mtg_CMSUtil_DecryptSymKey_CME(SECKEYPrivateKey *privkey, SECItem *encKey, SECOidTag bulkalgtag)
{
    /* that's easy */
    CK_MECHANISM_TYPE target;
    PORT_Assert(bulkalgtag != SEC_OID_UNKNOWN);
    target = PK11_AlgtagToMechanism(bulkalgtag);
    if (bulkalgtag == SEC_OID_UNKNOWN || target == CKM_INVALID_MECHANISM)
    {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        return NULL;
    }
    return PK11_PubUnwrapSymKey(privkey, encKey, target, CKA_UNWRAP, 0);
}
