//
// Created by sdeligeorgopoulos on 23.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PK11OBJ_H
#define MOZILLA_PROJECTS_MTG_PK11OBJ_H

#define MTG_GET_SIG_LEN()\
    case spxKey:\
        rv = PK11_ReadAttribute(key->pkcs11Slot, key->pkcs11ID, CKA_SPX_ALGORITHM, NULL, &attributeItem);\
        if (rv == SECSuccess) {\
            CK_ULONG mode = *((CK_ULONG *) attributeItem.data);\
            length = mode == 1 ? 49216 : 29792;\
            PORT_Free(attributeItem.data);\
            if (length != 0) {\
                return length;\
            }\
        }\
        return pk11_backupGetSignLength(key);

#endif //MOZILLA_PROJECTS_MTG_PK11OBJ_H
