//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_CERTDB_H
#define MOZILLA_PROJECTS_MTG_CERTDB_H

#define MTG_GET_KEY_USAGE()\
    case spxKey:\
        requiredUsage |= KU_DIGITAL_SIGNATURE;\
        break;\
    case cmeKey:\
        requiredUsage |= KU_KEY_ENCIPHERMENT;\
        break;

#endif //MOZILLA_PROJECTS_MTG_CERTDB_H
