//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_SECOIDT_H
#define MOZILLA_PROJECTS_MTG_SECOIDT_H

#define MTG_GET_OIDS()\
    SEC_OID_TLS_CME_SPX = 357,\
    SEC_OID_TLS_CMEE_SPX = 358,\
    SEC_OID_SPX_KEY = 359,\
    SEC_OID_SPX_SHA512_SIGNATURE = 360,\
    SEC_OID_CME_KEY = 361,\
    SEC_OID_CME_WRAP = 362

#define MTG_OID_DEFS()\
    static const unsigned char spx_with_sha512[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xae, 0x5d, 0x04, 0x01, 0x02, 0x02, 0x01, 0x01 };\
    static const unsigned char spx_key[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xae, 0x5d, 0x04, 0x01, 0x02, 0x01 };\
    static const unsigned char cme_wrap[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xae, 0x5d, 0x04, 0x01, 0x01, 0x02, 0x02, 0x01 };\
    static const unsigned char cme_key[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xae, 0x5d, 0x04, 0x01, 0x01, 0x01 };

#define MTG_GET_ODES()\
    ODE(SEC_OID_TLS_CME_SPX, "TLS_CME_SPX", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION),\
    ODE(SEC_OID_TLS_CMEE_SPX, "TLS_CMEE_SPX", CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION),\
    OD(spx_key, SEC_OID_SPX_KEY, "SPX Key", CKM_SPX_KEY, INVALID_CERT_EXTENSION),\
    OD(spx_with_sha512, SEC_OID_SPX_SHA512_SIGNATURE, "SHA512_WITH_SPX", CKM_SHA512_SPX, INVALID_CERT_EXTENSION),\
    OD(cme_key, SEC_OID_CME_KEY, "CME Key", CKM_CME_KEY, INVALID_CERT_EXTENSION),\
    OD(cme_wrap, SEC_OID_CME_WRAP, "CME_WRAP", CKM_CME_WRAP, INVALID_CERT_EXTENSION)

#endif //MOZILLA_PROJECTS_MTG_SECOIDT_H
