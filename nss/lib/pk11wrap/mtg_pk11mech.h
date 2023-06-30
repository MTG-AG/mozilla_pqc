//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PK11MECH_H
#define MOZILLA_PROJECTS_MTG_PK11MECH_H

#define MTG_GET_WRAP_CKM_FOR_KEY_TYPE()\
    case cmeKey:\
        return CKM_CME_WRAP;

#define MTG_GET_SIGN_CKM_FOR_SIGN_KEY_TYPE()\
    case spxKey:\
        return CKM_SHA512_SPX;

#endif //MOZILLA_PROJECTS_MTG_PK11MECH_H
