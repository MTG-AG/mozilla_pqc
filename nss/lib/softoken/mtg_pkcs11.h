//
// Created by sdeligeorgopoulos on 21.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PKCS11_H
#define MOZILLA_PROJECTS_MTG_PKCS11_H

#define MTG_HANDLE_KEY_TYPE()\
    case CKK_SPX:\
        if (!sftk_hasAttribute(object, CKA_SPX_ALGORITHM)) return CKR_TEMPLATE_INCOMPLETE;\
        if (!sftk_hasAttribute(object, CKA_VALUE)) return CKR_TEMPLATE_INCOMPLETE;\
        encrypt = CK_FALSE;\
        sign = CK_TRUE;\
        recover = CK_FALSE;\
        wrap = CK_FALSE;\
        createObjectInfo = PR_FALSE;\
        break;\
    case CKK_CME:\
        if (!sftk_hasAttribute(object, CKA_VALUE)) return CKR_TEMPLATE_INCOMPLETE;\
        encrypt = CK_TRUE;\
        sign = CK_FALSE;\
        recover = CK_FALSE;\
        wrap = CK_TRUE;\
        createObjectInfo = PR_FALSE;\
        break;

#endif //MOZILLA_PROJECTS_MTG_PKCS11_H
