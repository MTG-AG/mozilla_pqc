//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_CERTUTIL_H
#define MOZILLA_PROJECTS_MTG_CERTUTIL_H

#define MTG_KEY_ARGS()\
    else if (PL_strcmp(arg, "spx") == 0) {\
        keytype = spxKey;\
    } else if (PL_strcmp(arg, "cme") == 0) {\
        keytype = cmeKey;\
    }

#define MTG_KEY_STUFF()\
    case spxKey:\
        mechanism = CKM_SPX_KEY;\
        arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);\
        if (arena == NULL)\
            return NULL;\
        SECKEYSpxParams *sphincsPlusParams = PORT_ArenaZAlloc(arena, sizeof(SECKEYSphincsPlusParams));\
        if (sphincsPlusParams == NULL)\
            return NULL;\
        sphincsPlusParams->version = *SECITEM_AllocItem(arena, NULL, 1);\
        sphincsPlusParams->version.type = siBuffer;\
        unsigned char version[] = {0x00};\
        sphincsPlusParams->version.data = version;\
        sphincsPlusParams->mode = *SECITEM_AllocItem(arena, NULL, 1);\
        sphincsPlusParams->mode.type = siBuffer;\
        unsigned char mode[] = {0x01};\
        sphincsPlusParams->mode.data = mode;\
        sphincsPlusParams->spxFullHeight = *SECITEM_AllocItem(arena, NULL, 1);\
        sphincsPlusParams->spxFullHeight.type = siBuffer;\
        unsigned char spxFullHeight[] = {0x44};\
        sphincsPlusParams->spxFullHeight.data = spxFullHeight;\
        sphincsPlusParams->spxD = *SECITEM_AllocItem(arena, NULL, 1);\
        sphincsPlusParams->spxD.type = siBuffer;\
        unsigned char spxD[] = {0x11};\
        sphincsPlusParams->spxD.data = spxD;\
        sphincsPlusParams->spxForsHeight = *SECITEM_AllocItem(arena, NULL, 1);\
        sphincsPlusParams->spxForsHeight.type = siBuffer;\
        unsigned char spxForsHeight[] = {0x0A};\
        sphincsPlusParams->spxForsHeight.data = spxForsHeight;\
        sphincsPlusParams->spxForsTrees = *SECITEM_AllocItem(arena, NULL, 1);\
        sphincsPlusParams->spxForsTrees.type = siBuffer;\
        unsigned char spxForsTrees[] = {0x1E};\
        sphincsPlusParams->spxForsTrees.data = spxForsTrees;\
        sphincsPlusParams->spxTreeDigest = *SECITEM_AllocItem(arena, NULL, 9);\
        sphincsPlusParams->spxTreeDigest.type = siBuffer;\
        unsigned char digOid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C};\
        sphincsPlusParams->spxTreeDigest.data = digOid;\
        params = (void *) sphincsPlusParams;\
        break;\
    case cmeKey:\
        mechanism = CKM_CME_KEY;\
        break;\

#define MTG_FREE_KEYSTUFF()\
    case spxKey:\
    case cmeKey:\
        PORT_FreeArena(arena, PR_FALSE);\
    break;

#endif //MOZILLA_PROJECTS_MTG_CERTUTIL_H
