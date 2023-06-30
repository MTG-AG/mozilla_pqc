//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PK11SKEY_H
#define MOZILLA_PROJECTS_MTG_PK11SKEY_H

//TODO
#define MTG_PK11_PubDerive()\
    case spxKey:\
    case cmeKey:\
        break;

#define MTG_PK11_PubDeriveWithKDF()\
    case cmeKey:\
        return PK11_PubDerive(privKey, pubKey, isSender, randomA, randomB,\
                derive, target, operation, keySize, wincx);

#endif //MOZILLA_PROJECTS_MTG_PK11SKEY_H
