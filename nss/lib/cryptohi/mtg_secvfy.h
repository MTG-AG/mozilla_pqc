//
// Created by sdeligeorgopoulos on 08.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_SECVFY_H
#define MOZILLA_PROJECTS_MTG_SECVFY_H

#define MTG_SIG_DEFS()\
    unsigned char spxsig[49216];

#define MTG_LIST_SIG_KEYS()\
    case spxKey:


#define MTG_GET_HASH_FOR_SIG_OID()\
    case SEC_OID_SPX_SHA512_SIGNATURE:\
        *hashalg = SEC_OID_SHA512;\
        break;


#define MTG_GET_ENC_FOR_SIG_OID()\
    case SEC_OID_SPX_SHA512_SIGNATURE:\
        *encalg = SEC_OID_SPX_SHA512_SIGNATURE;\
        break;\

#define MTG_IS_MTG(encAlg)\
    encAlg == SEC_OID_SPX_SHA512_SIGNATURE

#endif //MOZILLA_PROJECTS_MTG_SECVFY_H
