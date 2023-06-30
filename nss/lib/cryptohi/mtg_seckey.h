//
// Created by sdeligeorgopoulos on 05.11.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_SECKEY_H
#define MOZILLA_PROJECTS_MTG_SECKEY_H

SECStatus mtg_get_key_type_for_sec_tag(SECOidTag tag, KeyType *keyType);

SECStatus mtg_get_public_key_from_spki(SECKEYPublicKey *pubk, SECOidTag tag, SECItem *spki, const SECItem *algorithm_params);

SECStatus mtg_get_public_key_strength_in_bits(KeyType keyType, unsigned *bitSize);

SECStatus mtg_get_signature_len(const SECKEYPublicKey *pubk, unsigned *size);

SECStatus mtg_copy_public_key(const SECKEYPublicKey *pubk, SECKEYPublicKey *copyk);

SECStatus mtg_import_der_public_key(CK_KEY_TYPE type, SECItem *newDerKey, SECKEYPublicKey *pubk);

SECStatus mtg_get_CERTSubjectPublicKeyInfo_from_SECKEYPublicKey(SECKEYPublicKey *pubk, SECItem *params, CERTSubjectPublicKeyInfo *spki);

#endif //MOZILLA_PROJECTS_MTG_SECKEY_H
