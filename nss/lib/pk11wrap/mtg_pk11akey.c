//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#include "secmodi.h"
#include "pk11pub.h"
#include "pk11priv.h"

#include "mtg_pk11akey.h"

static CK_ATTRIBUTE sphincsPlusPubTemplate[] = {
        { CKA_SPX_ALGORITHM, NULL, 0 },
        { CKA_TOKEN, NULL, 0 },
        { CKA_VERIFY, NULL, 0 },
        { CKA_VERIFY_RECOVER, NULL, 0 },
};

static CK_RV
pk11_Attr2SecItem(PLArenaPool *arena, const CK_ATTRIBUTE *attr, SECItem *item)
{
    item->data = NULL;

    (void)SECITEM_AllocItem(arena, item, attr->ulValueLen);
    if (item->data == NULL) {
        return CKR_HOST_MEMORY;
    }
    PORT_Memcpy(item->data, attr->pValue, item->len);
    return CKR_OK;
}

// TODO make it a makro or handle mode otherwise
SECStatus mtg_prepare_attrs_for_keygen(CK_MECHANISM_TYPE type, void *param, CK_ATTRIBUTE **attrs, CK_ATTRIBUTE **pubTemplate, KeyType *keyType, CK_MECHANISM *test_mech)
{
    SECStatus rv;

    switch (type)
    {
        case CKM_SPX_KEY:
            *attrs = sphincsPlusPubTemplate;
            CK_ULONG mode = (((SECKEYSPXParams *) param)->mode.data)[0];
            PK11_SETATTRS(*attrs, CKA_SPX_ALGORITHM, &mode, sizeof(CK_ULONG));
            (*attrs)++;
            *pubTemplate = sphincsPlusPubTemplate;
            *keyType = spxKey;
            test_mech->mechanism = CKM_SPX_KEY;
            rv = SECSuccess;
            break;
        case CKM_CME_KEY:
            rv = SECSuccess;
            break;
        default:
            rv = SECFailure;
            break;
    }

    return rv;
}

// TODO make better
SECStatus mtg_retrieve_public_key_from_pkcs11(SECKEYPublicKey *pubKey, PLArenaPool *tmp_arena, CK_ATTRIBUTE *attrs, CK_ATTRIBUTE *template, PK11SlotInfo *slot, CK_OBJECT_HANDLE id,
                                              const CK_KEY_TYPE *pk11KeyType, const CK_OBJECT_CLASS *keyClass, CK_RV *crv)
{
    SECStatus rv;
    CK_ATTRIBUTE *mode, *value;
    unsigned long templateCount = 0;

    switch (pubKey->keyType)
    {
        case spxKey:
            mode = attrs;
            PK11_SETATTRS(attrs, CKA_SPX_ALGORITHM, NULL, 0);
            attrs++;
            value = attrs;
            PK11_SETATTRS(attrs, CKA_VALUE, NULL, 0);
            attrs++;
            templateCount = attrs - template;
            PR_ASSERT(templateCount <= sizeof(template) / sizeof(CK_ATTRIBUTE));
            *crv = PK11_GetAttributes(tmp_arena, slot, id, template, templateCount);
            if (*crv != CKR_OK)
            {
                rv = SECFailure;
                break;
            }

            if ((*keyClass != CKO_PUBLIC_KEY) || (*pk11KeyType != CKK_SPX))
            {
                rv = SECFailure;
                break;
            }

            SECKEYSPXParams *sphincsPlusParams = PORT_ArenaZAlloc(pubKey->arena, sizeof(SECKEYSPXParams));
            if (sphincsPlusParams == NULL)
            {
                rv = SECFailure;
                break;
            }

            // fill parameters
            sphincsPlusParams->version = *SECITEM_AllocItem(pubKey->arena, NULL, 1);
            sphincsPlusParams->version.type = siUnsignedInteger;
            unsigned char version[] = {0x00};
            sphincsPlusParams->version.data = version;
            sphincsPlusParams->spxFullHeight = *SECITEM_AllocItem(pubKey->arena, NULL, 1);
            sphincsPlusParams->spxFullHeight.type = siUnsignedInteger;
            unsigned char spxFullHeight[] = {0x44};
            sphincsPlusParams->spxFullHeight.data = spxFullHeight;
            sphincsPlusParams->spxD = *SECITEM_AllocItem(pubKey->arena, NULL, 1);
            sphincsPlusParams->spxD.type = siUnsignedInteger;
            unsigned char spxD[] = {0x11};
            sphincsPlusParams->spxD.data = spxD;
            sphincsPlusParams->spxForsHeight = *SECITEM_AllocItem(pubKey->arena, NULL, 1);
            sphincsPlusParams->spxForsHeight.type = siUnsignedInteger;
            unsigned char spxForsHeight[] = {0x0A};
            sphincsPlusParams->spxForsHeight.data = spxForsHeight;
            sphincsPlusParams->spxForsTrees = *SECITEM_AllocItem(pubKey->arena, NULL, 1);
            sphincsPlusParams->spxForsTrees.type = siUnsignedInteger;
            unsigned char spxForsTrees[] = {0x1E};
            sphincsPlusParams->spxForsTrees.data = spxForsTrees;
            sphincsPlusParams->spxTreeDigest = *SECITEM_AllocItem(pubKey->arena, NULL, 9);
            sphincsPlusParams->spxTreeDigest.type = siUnsignedInteger;
            unsigned char digOid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C};
            sphincsPlusParams->spxTreeDigest.data = digOid;

            *crv = pk11_Attr2SecItem(pubKey->arena, mode, &pubKey->u.spx.params.mode);
            if (*crv != CKR_OK){
                rv = SECFailure;
                break;
            }

            *crv = pk11_Attr2SecItem(pubKey->arena, value, &pubKey->u.spx.keyData);
            if (*crv != CKR_OK){
                rv = SECFailure;
                break;
            }

            rv = SECSuccess;
            break;
        case cmeKey:
        default:
            rv = SECFailure;
            break;
    }

    return rv;
}

static CK_ATTRIBUTE_TYPE spxPrivUsage[] = {CKA_SIGN};
static CK_ATTRIBUTE_TYPE cmePrivUsage[] = {CKA_UNWRAP, CKA_DECRYPT};

SECStatus mtg_set_priv_key_usage(KeyType keyType, unsigned int keyUsage, CK_ATTRIBUTE_TYPE **usage, int *usageCount)
{
    SECStatus rv;

    switch (keyType)
    {
        case spxKey:
            if (keyUsage & KU_DIGITAL_SIGNATURE)
            {
                *usage = spxPrivUsage;
                *usageCount = sizeof(spxPrivUsage) / sizeof(CK_ATTRIBUTE_TYPE);
                rv = SECSuccess;
            }
            else
            {
                rv = SECFailure;
            }
            break;
        case cmeKey:
            if (keyUsage & KU_KEY_ENCIPHERMENT)
            {
                *usage = cmePrivUsage;
                *usageCount = sizeof(cmePrivUsage) / sizeof(CK_ATTRIBUTE_TYPE);
                rv = SECSuccess;
            }
            else
            {
                rv = SECFailure;
            }
            break;
        default:
            rv = SECFailure;
            break;
    }

    return rv;
}