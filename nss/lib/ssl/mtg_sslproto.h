//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MTG_SSLPROTO_H
#define MTG_SSLPROTO_H

/*MTG PQC cipher suites */
#define TLS_CME_SPX_WITH_AES_256_GCM_SHA256    0xFFF1
#define TLS_CMEE_SPX_WITH_AES_256_GCM_SHA256   0xFFF2

// For security/manager/ssl/nsNSSCallbacks.cpp:AccumulateCipherSuite:927
#define MTG_TLS_CIPHERSUITES_CPP() \
    case TLS_CME_SPX_WITH_AES_256_GCM_SHA256: value = 73; break; \
    case TLS_CMEE_SPX_WITH_AES_256_GCM_SHA256: value = 74; break;

// For security/manager/ssl/nsNSSCallbacks.cpp:HandshakeCallback:1156
#define MTG_TLS_KEAS() \
    case ssl_kea_cme: \
        AccumulateNonECCKeySize(Telemetry::SSL_KEA_RSA_KEY_SIZE_FULL, channelInfo.keaKeyBits); \
        break;

// For security/manager/ssl/nsNSSCallbacks.cpp:HandshakeCallback:1177
#define MTG_TLS_AUTH() \
    case ssl_auth_cme: \
    case ssl_auth_spx: \
        AccumulateNonECCKeySize(Telemetry::SSL_KEA_RSA_KEY_SIZE_FULL, channelInfo.authKeyBits); \
        break;

// For security/manager/ssl/nsNSSCallbacks.cpp:getSignatureName:701
#define MTG_TLS_SIGS_NAMES() \
    case ssl_sig_spx_sha512: \
        signatureName = NS_LITERAL_CSTRING("SPX-SHA512"); \
        break;

// For security/manager/ssl/nsNSSComponent.cpp:sCipherPrefs:1195
#define MTG_INCLUDE_TLS_CIPHERSUITES_CPP() \
    { "security.ssl3.cme_spx_aes_256_gcm_sha256", TLS_CME_SPX_WITH_AES_256_GCM_SHA256, true }, \
    { "security.ssl3.cmee_spx_aes_256_gcm_sha256", TLS_CMEE_SPX_WITH_AES_256_GCM_SHA256, true },


// For security/manager/ssl/nsNSSIOLayer.cpp:sEnabledSignatureSchemes:2505
#define MTG_INCLUDE_TLS_SIGS() \
    ssl_sig_spx_sha512,


#endif //MTG_SSLPROTO_H
