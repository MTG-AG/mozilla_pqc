//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_SSL3PROT_H
#define MOZILLA_PROJECTS_MTG_SSL3PROT_H

#define MTG_GET_KEA()\
    kea_cme_spx,\
    kea_cmee_spx

#define MTG_GET_CLIENT_CERT_TYPES()\
    ct_SPX_sign = 67,\
    ct_SPX_fixed_CME = 68

#endif //MOZILLA_PROJECTS_MTG_SSL3PROT_H
