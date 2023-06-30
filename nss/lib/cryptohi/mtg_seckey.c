//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#include <secoidt.h>
#include "certt.h"
#include "keythi.h"
#include "keyhi.h"

const SEC_ASN1Template SECKEY_CMEPublicKeyTemplate[] = {
        { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(SECKEYPublicKey) },
        { SEC_ASN1_INTEGER, offsetof(SECKEYPublicKey, u.cme.n) },
        { SEC_ASN1_INTEGER, offsetof(SECKEYPublicKey, u.cme.t) },
        { SEC_ASN1_OCTET_STRING, offsetof(SECKEYPublicKey, u.cme.keyData) },
        { 0 }
};

const SEC_ASN1Template SECKEY_SpxPublicKeyTemplate[] = {
        { SEC_ASN1_OCTET_STRING, offsetof(SECKEYPublicKey, u.spx.keyData) },
        { 0 }
};

const SEC_ASN1Template SECKEY_SpxParamKeyTemplate[] = {
        { SEC_ASN1_SEQUENCE,  0, NULL, sizeof(SECKEYSPXParams)},
        { SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, version)},
        { SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, mode)},
        { SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, spxFullHeight)},
        { SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, spxD)},
        { SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, spxForsHeight)},
        { SEC_ASN1_INTEGER,   offsetof(SECKEYSPXParams, spxForsTrees)},
        { SEC_ASN1_OBJECT_ID, offsetof(SECKEYSPXParams, spxTreeDigest)},
        { 0 }
};

static void
prepare_cme_pub_key_for_asn1(SECKEYPublicKey *pubk)
{
    pubk->u.cme.n.type = siUnsignedInteger;
    pubk->u.cme.t.type = siUnsignedInteger;
}

static void prepare_spx_key_params_for_asn1(SECKEYSPXParams *params)
{
    params->version.type = siUnsignedInteger;
    params->mode.type = siUnsignedInteger;
    params->spxFullHeight.type = siUnsignedInteger;
    params->spxD.type = siUnsignedInteger;
    params->spxForsHeight.type = siUnsignedInteger;
    params->spxForsTrees.type = siUnsignedInteger;
}

SECStatus mtg_get_key_type_for_sec_tag(SECOidTag tag, KeyType *keyType)
{
    SECStatus rv;

    switch (tag)
    {
        case SEC_OID_SPX_SHA512_SIGNATURE:
        case SEC_OID_SPX_KEY:
            *keyType = spxKey;
            rv = SECSuccess;
        break;
        case SEC_OID_CME_WRAP:
        case SEC_OID_CME_KEY:
            *keyType = cmeKey;
            rv = SECSuccess;
        break;
    default:
        rv = SECFailure;
        break;
    }

    return rv;
}

SECStatus mtg_get_public_key_from_spki(SECKEYPublicKey *pubk, SECOidTag tag, SECItem *spki, const SECItem *algorithm_params)
{
    SECItem newParms;

    SECStatus rv;

    switch (tag)
    {
        case SEC_OID_SPX_SHA512_SIGNATURE:
        case SEC_OID_SPX_KEY:
            pubk->keyType = spxKey;
            rv = SEC_QuickDERDecodeItem(pubk->arena, pubk, SECKEY_SpxPublicKeyTemplate, spki);
            if (rv != SECSuccess)
                break;

            /* copy the DER into the arena, since Quick DER returns data that points
               into the DER input, which may get freed by the caller */
            rv = SECITEM_CopyItem(pubk->arena, &newParms, algorithm_params);
            if (rv != SECSuccess)
                break;

            prepare_spx_key_params_for_asn1(&pubk->u.spx.params);
            rv = SEC_QuickDERDecodeItem(pubk->arena, &pubk->u.spx.params, SECKEY_SpxParamKeyTemplate,
                                        &newParms);
            break;
        case SEC_OID_CME_KEY:
        case SEC_OID_CME_WRAP:
            prepare_cme_pub_key_for_asn1(pubk);
            pubk->keyType = cmeKey;
            rv = SEC_QuickDERDecodeItem(pubk->arena, pubk, SECKEY_CMEPublicKeyTemplate, spki);
            break;

        default:
            rv = SECFailure;
    }

    return rv;
}

SECStatus mtg_get_public_key_strength_in_bits(KeyType keyType, unsigned *bitSize)
{
    SECStatus rv;

    switch (keyType) {
        case spxKey:
            *bitSize = 64*8; // TODO check
            rv = SECSuccess;
            break;
        case cmeKey:
            *bitSize = 256 * 8; // TODO check
            rv = SECSuccess;
            break;
        default:
            rv = SECFailure;
            break;
    }

    return rv;
}

SECStatus mtg_get_signature_len(const SECKEYPublicKey *pubk, unsigned *size)
{
    SECStatus rv;

    switch (pubk->keyType) {
        case spxKey:
            *size = pubk->u.spx.params.mode.data[0] ? 49216 : 29792;
            rv = SECSuccess;
            break;
        default:
            rv = SECFailure;
            break;
    }

    return rv;
}

SECStatus mtg_copy_public_key(const SECKEYPublicKey *pubk, SECKEYPublicKey *copyk)
{
    SECStatus rv;

    switch (pubk->keyType) {
        case spxKey:
            rv = SECITEM_CopyItem(copyk->arena, &copyk->u.spx.params.mode, &pubk->u.spx.params.mode);
            if (rv != SECSuccess)
                break;
            rv = SECITEM_CopyItem(copyk->arena, &copyk->u.spx.params.version, &pubk->u.spx.params.version);
            if (rv != SECSuccess)
                break;
            rv = SECITEM_CopyItem(copyk->arena, &copyk->u.spx.params.spxD, &pubk->u.spx.params.spxD);
            if (rv != SECSuccess)
                break;
            rv = SECITEM_CopyItem(copyk->arena, &copyk->u.spx.params.spxForsHeight, &pubk->u.spx.params.spxForsHeight);
            if (rv != SECSuccess)
                break;
            rv = SECITEM_CopyItem(copyk->arena, &copyk->u.spx.params.spxForsTrees, &pubk->u.spx.params.spxForsTrees);
            if (rv != SECSuccess)
                break;
            rv = SECITEM_CopyItem(copyk->arena, &copyk->u.spx.params.spxFullHeight, &pubk->u.spx.params.spxFullHeight);
            if (rv != SECSuccess)
                break;
            rv = SECITEM_CopyItem(copyk->arena, &copyk->u.spx.params.spxTreeDigest, &pubk->u.spx.params.spxTreeDigest);
            if (rv != SECSuccess)
                break;
            rv = SECITEM_CopyItem(copyk->arena, &copyk->u.spx.keyData, &pubk->u.spx.keyData);
            break;
        default:
            rv = SECFailure;
            break;
    }

    return rv;
}

SECStatus mtg_import_der_public_key(CK_KEY_TYPE type, SECItem *newDerKey, SECKEYPublicKey *pubk)
{
    SECStatus rv;
    CERTSubjectPublicKeyInfo *spki;

    switch(type)
    {
        case CKK_CME:
        case CKK_SPX:
            /* decode the subject public key info */
            spki = SECKEY_DecodeDERSubjectPublicKeyInfo(newDerKey);
            if (spki == NULL) {
                rv = SECFailure;
                break;
            }
            
            /* Convert bit string length from bits to bytes */
            DER_ConvertBitString(&spki->subjectPublicKey);

            SECItem subjectPublicKey;
            rv = SECITEM_CopyItem(pubk->arena, &subjectPublicKey, &spki->subjectPublicKey);
            if (rv != SECSuccess) {
                rv = SECFailure;
                SECKEY_DestroySubjectPublicKeyInfo(spki);
                break;
            }


            SECOidTag tag = SECOID_GetAlgorithmTag(&spki->algorithm);

            /* get the public key */
            rv = mtg_get_public_key_from_spki(pubk, tag, &subjectPublicKey, &spki->algorithm.parameters);

            SECKEY_DestroySubjectPublicKeyInfo(spki);
            break;

        default:
            rv = SECFailure;
    }

    return rv;
}

SECStatus mtg_get_CERTSubjectPublicKeyInfo_from_SECKEYPublicKey(SECKEYPublicKey *pubk, SECItem *params, CERTSubjectPublicKeyInfo *spki)
{
    SECStatus rv;

    SECItem *rv_item;

    switch (pubk->keyType)
    {
        case spxKey:
            /* DER encode the params. */
            prepare_spx_key_params_for_asn1(&pubk->u.spx.params);
            rv_item = SEC_ASN1EncodeItem(spki->arena, params, &pubk->u.spx.params,
                                         SECKEY_SpxParamKeyTemplate);
            if (rv_item != NULL) {
                rv = SECOID_SetAlgorithmID(spki->arena, &spki->algorithm,
                                           SEC_OID_SPX_SHA512_SIGNATURE,
                                           params);
                if (rv == SECSuccess) {
                    /*
                     * DER encode the public key into the subjectPublicKeyInfo.
                     */
                    rv_item = SEC_ASN1EncodeItem(spki->arena, &spki->subjectPublicKey,
                                                 pubk,
                                                 SECKEY_SpxPublicKeyTemplate);
                    if (rv_item != NULL) {
                        /*
                         * The stored value is supposed to be a BIT_STRING,
                         * so convert the length.
                         */
                        spki->subjectPublicKey.len <<= 3;
                        /*
                         * We got a good one; return it.
                         */
                        rv = SECSuccess;
                        break;
                    }
                }
            }
            rv = SECFailure;
            SECITEM_FreeItem(params, PR_FALSE);
            break;
        case cmeKey:
            rv = SECOID_SetAlgorithmID(spki->arena, &spki->algorithm,
                                       SEC_OID_CME_KEY, 0);
            if (rv == SECSuccess) {
                /*
                 * DER encode the public key into the subjectPublicKeyInfo.
                 */
                prepare_cme_pub_key_for_asn1(pubk);
                rv_item = SEC_ASN1EncodeItem(spki->arena, &spki->subjectPublicKey,
                                             pubk, SECKEY_CMEPublicKeyTemplate);
                if (rv_item != NULL) {
                    /*
                     * The stored value is supposed to be a BIT_STRING,
                     * so convert the length.
                     */
                    spki->subjectPublicKey.len <<= 3;
                    /*
                     * We got a good one; return it.
                     */
                    rv = SECSuccess;
                    break;
                }
            }
            rv = SECFailure;
            break;
        default:
            rv = SECFailure;
    }

    return rv;
}

