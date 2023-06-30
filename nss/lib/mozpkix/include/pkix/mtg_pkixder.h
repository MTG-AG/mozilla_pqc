//
// Created by sdeligeorgopoulos on 27.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_PKIXDER_H
#define MOZILLA_PROJECTS_MTG_PKIXDER_H

// for Input.h

//   changed from uint16_t to typedef uint32_t size_type; to accommodate asn1 structs with lengths of more than 2 bytes

#define MTG_MAX_HANDSHAKE_MSG_LEN 0xffE0000

#define MTG_PARSE_3_LEN_BYTES() \
    Result Read3Bytes(uint32_t& out) { \
        Result rv = EnsureLength(3);\
        if (rv != Success) {\
            return rv;\
        }\
        out = *input++;\
        out <<= 8u;\
        out |= *input++;\
        out <<= 8u;\
        out |= *input++;\
        return Success;\
    }

// for pkixder_universal_types_tests.cpp

#define MTG_INVALID 0xFFU

// for pkixder.h

#define MTG_PUBLIC_KEY_ALGORITHMS SPX, CME

// for pkixder.cpp

#define MTG_LENGTH_CASE() \
      else if (length1 == 0x83) { \
        uint32_t length3; \
        rv = input.Read3Bytes(length3); \
        if (rv != Success) { \
            return rv; \
        } \
        if (length3 < 256) { \
            return Result::ERROR_BAD_DER; \
        } \
        return input.Skip(length3, value); \
      }

#define MTG_SIG_OID_DEFS()\
    static const uint8_t spx_with_sha512[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xae, 0x5d, 0x04, 0x01, 0x02, 0x02, 0x01, 0x01 };

#define MTG_HANDLE_PUB_OID()\
    else if (algorithmID.MatchRest(spx_with_sha512)) {\
        publicKeyAlgorithm = PublicKeyAlgorithm::SPX; \
        digestAlgorithm = DigestAlgorithm::sha512; \
    }

// for pkixcheck.cpp

//TODO think if a check has meaning here
#define MTG_HANDLE_PUB_KEYS() \
    case der::PublicKeyAlgorithm::SPX: \
    case der::PublicKeyAlgorithm::CME: \
    { \
        break; \
    }

#define MTG_PKIX_OID_DEFS()\
    static const uint8_t spx_key[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xae, 0x5d, 0x04, 0x01, 0x02, 0x01 };\
    static const uint8_t cme_key[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xae, 0x5d, 0x04, 0x01, 0x01, 0x01 };

//TODO think if a check has meaning here
#define MTG_HANDLE_OIDS()\
    else if (algorithmOID.MatchRest(spx_key)) {\
        return Success; \
    } \
    else if (algorithmOID.MatchRest(cme_key)) {\
        return Success; \
    }

// for pkixverify.cpp
// here all mtg algs are mapped to the VerifyRSAPKCS1SignedDigest and then in pkixnss.cpp:VerifySignedDigest the actual
// differentiation takes place
#define MTG_HANDLDE_SIG_PUB_KEYS() \
    case der::PublicKeyAlgorithm::SPX: \
        return trustDomain.VerifyRSAPKCS1SignedDigest(signedDigest, signerSubjectPublicKeyInfo);

#endif //MOZILLA_PROJECTS_MTG_PKIXDER_H
