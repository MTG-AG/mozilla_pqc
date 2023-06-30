//
// Created by sdeligeorgopoulos on 06.02.2019.
//
#include "pk11pub.h"
#include "mtg_p12d.h"

SECStatus mtg_import_cert_for_key_to_slot(CERTCertificate *cert, char *nickname, PRBool addCertUsage, void *wincx)
{
    SECStatus rv;
    PK11SlotInfo *mtgSlot;

    switch (SECOID_FindOIDTag(&cert->signature.algorithm))
    {
        case SEC_OID_SPX_SHA512_SIGNATURE:
        case SEC_OID_SPX_KEY:
        case SEC_OID_CME_KEY:
        case SEC_OID_CME_WRAP:
            mtgSlot = PK11_GetBestSlot(CKM_CME_WRAP, wincx);
            rv = PK11_ImportCertForKeyToSlot(mtgSlot, cert, nickname, addCertUsage, wincx);
            PK11_FreeSlot(mtgSlot);
            break;
        default:
            rv = SECFailure;
            break;
    }

    return rv;
}

SECStatus mtg_import_encrypted_private_key_info(SECKEYEncryptedPrivateKeyInfo *epki, SECItem *pwitem,
                                                SECItem *nickname, SECItem *publicValue, PRBool isPerm,
                                                PRBool isPrivate, KeyType keyType,
                                                unsigned int keyUsage, void *wincx)
{
    SECStatus rv;
    PK11SlotInfo *mtgSlot;

    switch (keyType)
    {
        case spxKey:
        case cmeKey:
            mtgSlot = PK11_GetBestSlot(CKM_CME_WRAP, wincx);
            rv = PK11_ImportEncryptedPrivateKeyInfo(mtgSlot, epki, pwitem, nickname, publicValue,
                                                    isPerm, isPrivate, keyType, keyUsage, wincx);
            PK11_FreeSlot(mtgSlot);
            break;
        default:
            rv = SECFailure;
            break;
    }

    return rv;
}

SECStatus mtg_import_public_key(SECKEYPublicKey *publicKey, PRBool isToken, void *wincx)
{
    SECStatus rv;
    PK11SlotInfo *mtgSlot;

    switch (publicKey->keyType)
    {
        case spxKey:
        case cmeKey:
            mtgSlot = PK11_GetBestSlot(CKM_CME_WRAP, wincx);
            PK11_ImportPublicKey(mtgSlot, publicKey, isToken);
            PK11_FreeSlot(mtgSlot);
            rv = SECSuccess;
            break;
        default:
            rv = SECFailure;
            break;
    }

    return rv;
}
