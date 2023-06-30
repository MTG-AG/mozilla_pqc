//
// Created by sdeligeorgopoulos on 12.11.2018.
//

#include <sqlite3.h>
#include "secdert.h"
#include "secasn1.h"
#include "secoid.h"
#include "lowkeyti.h"
#include "pkcs11i.h"
#include "mtg_pkcs11c.h"

//const SEC_ASN1Template SECKEY_CMEPublicKeyTemplate[] = {
//        { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(SECKEYPublicKey) },
//        { SEC_ASN1_INTEGER, offsetof(SECKEYPublicKey, u.cme.n) },
//        { SEC_ASN1_INTEGER, offsetof(SECKEYPublicKey, u.cme.t) },
//        { SEC_ASN1_OCTET_STRING, offsetof(SECKEYPublicKey, u.cme.keyData) },
//        { 0 }
//};

const SEC_ASN1Template SECKEY_CMEPrivateKeyTemplate[] = {
        {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(MTGPrivateKey)},
        {SEC_ASN1_INTEGER,      offsetof(MTGPrivateKey, u.cme.n)},
        {SEC_ASN1_INTEGER,      offsetof(MTGPrivateKey, u.cme.t)},
        {SEC_ASN1_OCTET_STRING, offsetof(MTGPrivateKey, u.cme.keyData)},
        {0}
};

//const SEC_ASN1Template SECKEY_SpxPublicKeyTemplate[] = {
//        { SEC_ASN1_OCTET_STRING, offsetof(SECKEYPublicKey, u.spx.keyData) },
//        { 0 }
//};

const SEC_ASN1Template SECKEY_SpxPrivateKeyTemplate[] = {
        {SEC_ASN1_OCTET_STRING, offsetof(MTGPrivateKey, u.spx.keyData)},
        {0}
};

const SEC_ASN1Template SECKEY_SpxPrivParamKeyTemplate[] = {
        {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(SECKEYSPXParams)},
        {SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, version)},
        {SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, mode)},
        {SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, spxFullHeight)},
        {SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, spxD)},
        {SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, spxForsHeight)},
        {SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, spxForsTrees)},
        {SEC_ASN1_OBJECT_ID, offsetof(SECKEYSPXParams, spxTreeDigest)},
        {0}
};

static void prepare_cme_priv_key_for_asn1(MTGPrivateKey *privateKey)
{
    privateKey->u.cme.n.type = siUnsignedInteger;
    privateKey->u.cme.t.type = siUnsignedInteger;
}


static void prepare_spx_key_params_for_asn1(SECKEYSPXParams *params)
{
    params->version.type = siUnsignedInteger;
    params->spxFullHeight.type = siUnsignedInteger;
    params->spxD.type = siUnsignedInteger;
    params->spxForsHeight.type = siUnsignedInteger;
    params->spxForsTrees.type = siUnsignedInteger;
}

SECStatus mtg_store_priv_key(PLArenaPool *arena, NSSLOWKEYPrivateKeyInfo *pki, SFTKObject *key)
{
    SECStatus rv;
    CK_BBOOL cktrue = CK_TRUE;
    const SEC_ASN1Template *keyTemplate = NULL;
    const SEC_ASN1Template *paramTemplate = NULL;
    void *paramDest = NULL;
    MTGPrivateKey privKey;

    SECOidTag tag = SECOID_GetAlgorithmTag(&pki->algorithm);

    switch (tag)
    {
        case SEC_OID_SPX_KEY:
            privKey.keyType = CKK_SPX;
            keyTemplate = SECKEY_SpxPrivateKeyTemplate;
            paramTemplate = SECKEY_SpxPrivParamKeyTemplate;
            paramDest = &(privKey.u.spx.params);
            prepare_spx_key_params_for_asn1(&privKey.u.spx.params);
            rv = SECSuccess;
            break;
        case SEC_OID_CME_KEY:
            privKey.keyType = CKK_CME;
            keyTemplate = SECKEY_CMEPrivateKeyTemplate;
            prepare_cme_priv_key_for_asn1(&privKey);
            rv = SECSuccess;
            break;
        default:
            rv = SECFailure;
            break;
    }

    if (rv == SECSuccess)
    {
        /* decode the private key and any algorithm parameters */
        if ((rv = SEC_QuickDERDecodeItem(arena, &privKey, keyTemplate, &pki->privateKey)) == SECSuccess)
        {
            if (paramDest && paramTemplate)
            {
                rv = SEC_QuickDERDecodeItem(arena, paramDest, paramTemplate, &(pki->algorithm.parameters));
            }

            if (rv == SECSuccess)
            {
                CK_RV crv;
                switch (privKey.keyType)
                {
                    case CKK_SPX:
                        crv = sftk_AddAttributeType(key, CKA_KEY_TYPE, &privKey.keyType, sizeof(privKey.keyType));
                        if (crv != CKR_OK)
                            break;
                        crv = sftk_AddAttributeType(key, CKA_SIGN, &cktrue, sizeof(CK_BBOOL));
                        if (crv != CKR_OK)
                            break;
                        crv = sftk_AddAttributeType(key, CKA_VALUE, sftk_item_expand(&privKey.u.spx.keyData));
                        if (crv != CKR_OK)
                            break;
                        CK_ULONG mode = privKey.u.spx.params.mode.data[0];
                        crv = sftk_AddAttributeType(key, CKA_SPX_ALGORITHM, &mode, sizeof(CK_ULONG));
                        if (crv != CKR_OK)
                            break;
                        break;
                    case CKK_CME:
                        crv = sftk_AddAttributeType(key, CKA_KEY_TYPE, &privKey.keyType, sizeof(privKey.keyType));
                        if (crv != CKR_OK)
                            break;
                        crv = sftk_AddAttributeType(key, CKA_DECRYPT, &cktrue, sizeof(CK_BBOOL));
                        if (crv != CKR_OK)
                            break;
                        crv = sftk_AddAttributeType(key, CKA_UNWRAP, &cktrue, sizeof(CK_BBOOL));
                        if (crv != CKR_OK)
                            break;
                        crv = sftk_AddAttributeType(key, CKA_VALUE, sftk_item_expand(&privKey.u.cme.keyData));
                        if (crv != CKR_OK)
                            break;
                        break;
                    default:
                        crv = CKR_TEMPLATE_INCONSISTENT;
                        break;
                }

                privKey.arena = arena;

                if (crv == CKR_OK)
                {
                    rv = SECSuccess;
                }
                else
                {
                    rv = SECFailure;
                }
            }
        }
    }

    return rv;
}
