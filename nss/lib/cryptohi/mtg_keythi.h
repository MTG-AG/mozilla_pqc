//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_KEYTHI_H
#define MOZILLA_PROJECTS_MTG_KEYTHI_H

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

#define MTG_PUBLIC_KEYS()\
    SECKEYCMEKey cme;\
    SECKEYSPXKey spx;

#define MTG_GET_KEY_TYPES()\
    spxKey = 9,\
    cmeKey = 10

SEC_BEGIN_PROTOS
extern const SEC_ASN1Template SECKEY_CMEPublicKeyTemplate[];
extern const SEC_ASN1Template SECKEY_SpxPublicKeyTemplate[];
extern const SEC_ASN1Template SECKEY_SpxParamKeyTemplate[];
SEC_END_PROTOS

// For comm/mailnews/extensions/smime/nsMsgComposeSecure.cpp:GetSigningHashFunction:349
#define MTG_HASH_FOR_SIG_KEY_CPP() \
    else if (subjectPublicKeyType == spxKey) {\
        *hashType = nsICryptoHash::SHA512;\
    }

#endif //MOZILLA_PROJECTS_MTG_KEYTHI_H
