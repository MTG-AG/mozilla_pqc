//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_SSLT_H
#define MOZILLA_PROJECTS_MTG_SSLT_H

#define MTG_GET_KEA_TYPES()\
    ssl_kea_cme = 8

#define MTG_GET_SIGN_TYPES()\
    ssl_sign_spx = 4

#define MTG_GET_SIGNATURE_SCHEMES()\
    ssl_sig_spx_sha512 = 0x0614

#define MTG_GET_AUTH_TYPES()\
    ssl_auth_spx = 11,\
    ssl_auth_cme = 12

// used in netwerk/protocol/http/Http2Session.cpp:4213
#define MTG_HTTP2_KEA_CHECK()\
    && kea != ssl_kea_cme

#endif //MOZILLA_PROJECTS_MTG_SSLT_H
