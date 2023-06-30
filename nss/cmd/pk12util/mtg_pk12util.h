//
// Created by sdeligeorgopoulos on 21.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PK12UTIL_H
#define MOZILLA_PROJECTS_MTG_PK12UTIL_H

#include <secmod.h>

#define MTG_ADD_PKCS11_MODULE()\
    SECMODModule *module1 = SECMOD_LoadUserModule("library=../../../../dist/linux/x64/lib/libmtg_pkcs11.so name=\"MTG PKCS11\"", NULL, PR_FALSE);\
    if (module1 == NULL || !module1->loaded) {\
        const PRErrorCode err = PR_GetError();\
        fprintf(stderr, "Failed to Load MTG PKCS11: NSPR error code %d: %s\n",err, PR_ErrorToName(err));\
        exit(1);\
    }

#define MTG_DESTROY_PKCS11_MODULE()\
    SECMOD_DestroyModule(module1);

#endif //MOZILLA_PROJECTS_MTG_PK12UTIL_H
