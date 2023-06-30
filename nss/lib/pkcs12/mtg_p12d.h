//
// Created by sdeligeorgopoulos on 12.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_P12D_H
#define MOZILLA_PROJECTS_MTG_P12D_H

#define MTG_PUB_DATA_FOR_KEY_TYPE()\
        case cmeKey:\
            pubValue = &pubKey->u.cme.keyData;\
            break;\
        case spxKey:\
            pubValue = &pubKey->u.spx.keyData;\
            break;

SECStatus
mtg_import_cert_for_key_to_slot(CERTCertificate *cert, char *nickname, PRBool addCertUsage, void *wincx);

SECStatus
mtg_import_encrypted_private_key_info(SECKEYEncryptedPrivateKeyInfo *epki, SECItem *pwitem,
                                                SECItem *nickname, SECItem *publicValue, PRBool isPerm,
                                                PRBool isPrivate, KeyType keyType,
                                                unsigned int keyUsage, void *wincx);

SECStatus
mtg_import_public_key(SECKEYPublicKey *publicKey, PRBool isToken, void *wincx);

#endif //MOZILLA_PROJECTS_MTG_P12D_H
