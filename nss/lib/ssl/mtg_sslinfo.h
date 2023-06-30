//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_SSLINFO_H
#define MOZILLA_PROJECTS_MTG_SSLINFO_H

#define S_CME "CME", ssl_auth_cme
#define S_SPX "SPX", ssl_auth_spx

#define A_CME ssl_auth_cme
#define A_SPX ssl_auth_spx

#define K_CME "CME", ssl_kea_cme
#define K_CMEE "CMEE", ssl_kea_cme

#define MTG_GET_SUITE_INFO()\
    {0, CS(CME_SPX_WITH_AES_256_GCM_SHA256), S_CME, K_CME, C_AESGCM, B_256, M_AEAD_128, F_NFIPS_STD, A_CME },\
    {0, CS(CMEE_SPX_WITH_AES_256_GCM_SHA256), S_SPX, K_CMEE, C_AESGCM, B_256, M_AEAD_128, F_NFIPS_STD,  A_SPX }

#endif //MOZILLA_PROJECTS_MTG_SSLINFO_H
