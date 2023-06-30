//
// Created by sdeligeorgopoulos on 12.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PKCS11C_H
#define MOZILLA_PROJECTS_MTG_PKCS11C_H

struct SECKEYSPXParamsStr
{
    SECItem version;
    SECItem mode;
    SECItem spxFullHeight;
    SECItem spxD;
    SECItem spxForsHeight;
    SECItem spxForsTrees;
    SECItem spxTreeDigest;
};
typedef struct SECKEYSPXParamsStr SECKEYSPXParams;

struct SECKEYSPXKeyStr
{
    SECKEYSPXParams params;
    SECItem keyData;
};
typedef struct SECKEYSPXKeyStr SECKEYSPXKey;

struct SECKEYCMEKeyStr
{
    SECItem n;
    SECItem t;
    SECItem keyData;
};
typedef struct SECKEYCMEKeyStr SECKEYCMEKey;

struct MTGPrivateKeyStr
{
    PLArenaPool *arena;
    CK_KEY_TYPE keyType;
    union
    {
        SECKEYCMEKey cme;
        SECKEYSPXKey spx;
    } u;
};

typedef struct MTGPrivateKeyStr MTGPrivateKey;

extern const SEC_ASN1Template SECKEY_CMEPublicKeyTemplate[];
extern const SEC_ASN1Template SECKEY_CMEPrivateKeyTemplate[];
extern const SEC_ASN1Template SECKEY_SpxPublicKeyTemplate[];
extern const SEC_ASN1Template SECKEY_SpxPrivateKeyTemplate[];
extern const SEC_ASN1Template SECKEY_SpxPrivParamKeyTemplate[];

SECStatus mtg_store_priv_key(PLArenaPool *arena, NSSLOWKEYPrivateKeyInfo *pki, SFTKObject *key);

#endif //MOZILLA_PROJECTS_MTG_PKCS11C_H
