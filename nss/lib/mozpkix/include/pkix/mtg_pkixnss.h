//
// Created by sdeligeorgopoulos on 27.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PKIXNSS_H
#define MOZILLA_PROJECTS_MTG_PKIXNSS_H

// for pkixnss.cpp

#define MTG_OVERWRITE_SEC_OID() \
    switch(pubKey.get()->keyType)\
    {\
        case spxKey:\
            pubKeyAlg = SEC_OID_SPX_SHA512_SIGNATURE;\
            break;\
        default:\
            break;\
    }

#endif //MOZILLA_PROJECTS_MTG_PKIXNSS_H
