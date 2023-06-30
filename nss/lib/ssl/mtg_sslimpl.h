//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_SSLIMPL_H
#define MOZILLA_PROJECTS_MTG_SSLIMPL_H

#define MTG_NUMBER_OF_SUITES_IMPLEMENTED 2

#define MTG_NUMBER_OF_SIGNATURE_SCHEMES 1

/* PQC functions */
extern SECStatus ssl3_SendCMEServerKeyExchange(sslSocket *ss);
extern SECStatus ssl3_SendNHServerKeyExchange(sslSocket *ss);

extern SECStatus ssl3_SendCMEClientKeyExchange(sslSocket *ss,
                                               SECKEYPublicKey *svrPubKey);
extern SECStatus ssl3_SendNHClientKeyExchange(sslSocket *ss,
                                              SECKEYPublicKey *svrPubKey);

#endif //MOZILLA_PROJECTS_MTG_SSLIMPL_H
