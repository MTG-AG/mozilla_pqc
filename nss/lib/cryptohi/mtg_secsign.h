//
// Created by sdeligeorgopoulos on 08.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_SECSIGN_H
#define MOZILLA_PROJECTS_MTG_SECSIGN_H

#define MTG_GET_SIG_OIF_FOR_SIG_AND_HASH()\
    case spxKey:\
        switch (hashAlgTag) {\
            case SEC_OID_SHA512:\
                sigTag = SEC_OID_SPX_SHA512_SIGNATURE;\
                break;\
            default:\
                break;\
            }

#endif //MOZILLA_PROJECTS_MTG_SECSIGN_H
