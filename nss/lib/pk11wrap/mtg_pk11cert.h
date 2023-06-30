//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PK11CERT_H
#define MOZILLA_PROJECTS_MTG_PK11CERT_H

//TODO
#define MTG_PK11_IsUserCert()\
    case spxKey:\
    case cmeKey:\
        break;

#define MTG_GET_PUB_ID()\
        case cmeKey:\
            newItem = SECITEM_DupItem(&pubk->u.cme.keyData);\
            break;\
        case spxKey:\
            newItem = SECITEM_DupItem(&pubk->u.spx.keyData);\
            break;

#endif //MOZILLA_PROJECTS_MTG_PK11CERT_H
