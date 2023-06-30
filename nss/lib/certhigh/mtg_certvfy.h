//
// Created by sdeligeorgopoulos on 26.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_CERTVFY_H
#define MOZILLA_PROJECTS_MTG_CERTVFY_H
//TODO add correct value for cme
#define MTG_CHECK_KEY_PARAMS() \
    case SEC_OID_CME_WRAP: \
        if (key->keyType != cmeKey) { \
            PORT_SetError(SEC_ERROR_INVALID_ALGORITHM); \
            return SECFailure; \
        } \
        if (key->u.cme.keyData.len != 0) \
        {\
            return SECFailure;\
        }\
        return SECSuccess; \
    case SEC_OID_SPX_SHA512_SIGNATURE: \
        if (key->keyType != spxKey) { \
            PORT_SetError(SEC_ERROR_INVALID_ALGORITHM); \
            return SECFailure; \
        } \
        if (key->u.spx.keyData.len != 64) \
        { \
            return SECFailure;\
        }\
        return SECSuccess;


#endif //MOZILLA_PROJECTS_MTG_CERTVFY_H
