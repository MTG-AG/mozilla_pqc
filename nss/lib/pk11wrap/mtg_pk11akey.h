//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PK11AKEY_H
#define MOZILLA_PROJECTS_MTG_PK11AKEY_H

#define MTG_pk11_MakeIDFromPublicKey()\
    case spxKey:\
        pubKeyIndex = &pubKey->u.spx.keyData;\
        break;\
    case cmeKey:\
        pubKeyIndex = &pubKey->u.cme.keyData;\
        break;

#define MTG_GET_KEY_TYPE_FOR_CKK()\
    case CKK_SPX:\
        keyType = spxKey;\
        break;\
    case CKK_CME:\
        keyType = cmeKey;\
        break;

#define MTG_PRIV_KEY_ATTR()\
    case spxKey:\
        ap->type = CKA_VALUE;\
        ap++;\
        count++;\
        extra_count++;\
        ap->type = CKA_SIGN;\
        ap++;\
        count++;\
        extra_count++;\
        ap->type = CKA_SPX_ALGORITHM;\
        ap++;\
        count++;\
        extra_count++;\
        break;\
    case cmeKey:\
        ap->type = CKA_VALUE;\
        ap++;\
        count++;\
        extra_count++;\
        ap->type = CKA_DECRYPT;\
        ap++;\
        count++;\
        extra_count++;\
        ap->type = CKA_UNWRAP;\
        ap++;\
        count++;\
        extra_count++;\
        break;

#define MTG_PUB_KEY_ATTR()\
    case spxKey:\
        keyType = CKK_SPX;\
        PK11_SETATTRS(attrs, CKA_VERIFY, &cktrue, sizeof(CK_BBOOL));\
        attrs++;\
        signedattr = attrs;\
        CK_ULONG mode = pubKey->u.spx.params.mode.data[0];\
        PK11_SETATTRS(attrs, CKA_SPX_ALGORITHM, &mode, sizeof(CK_ULONG));\
        attrs++;\
        PK11_SETATTRS(attrs, CKA_VALUE, pubKey->u.spx.keyData.data, pubKey->u.spx.keyData.len);\
        attrs++;\
        break;\
    case cmeKey:\
        keyType = CKK_CME;\
        PK11_SETATTRS(attrs, CKA_ENCRYPT, &cktrue, sizeof(CK_BBOOL));\
        attrs++;\
        PK11_SETATTRS(attrs, CKA_WRAP, &cktrue, sizeof(CK_BBOOL));\
        attrs++;\
        signedattr = attrs;\
        PK11_SETATTRS(attrs, CKA_VALUE, pubKey->u.cme.keyData.data, pubKey->u.cme.keyData.len);\
        attrs++;\
        break;

SECStatus
mtg_prepare_attrs_for_keygen(CK_MECHANISM_TYPE type, void *param, CK_ATTRIBUTE **attrs, CK_ATTRIBUTE **pubTemplate,
                             KeyType *keyType, CK_MECHANISM *test_mech);

SECStatus mtg_retrieve_public_key_from_pkcs11(SECKEYPublicKey *pubKey, PLArenaPool *tmp_arena, CK_ATTRIBUTE *attrs,
                                              CK_ATTRIBUTE *template, PK11SlotInfo *slot, CK_OBJECT_HANDLE id,
                                              const CK_KEY_TYPE *pk11KeyType, const CK_OBJECT_CLASS *keyClass,
                                              CK_RV *crv);

SECStatus mtg_set_priv_key_usage(KeyType keyType, unsigned int keyUsage, CK_ATTRIBUTE_TYPE **usage, int *usageCount);

#endif //MOZILLA_PROJECTS_MTG_PK11AKEY_H
