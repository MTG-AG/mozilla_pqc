//
// Created by sdeligeorgopoulos on 04.12.2018.
//

#ifndef MOZILLA_PROJECTS_MTG_SMIMEUTIL_H
#define MOZILLA_PROJECTS_MTG_SMIMEUTIL_H

#define MTG_CHOOSE_SMIME_CHIPHER() \
    else if (key_type == cmeKey) { \
        chosen_cipher = SMIME_AES_CBC_256;\
        cipher_abilities[aes256_mapi]++;\
        cipher_votes[aes256_mapi] += pref;\
        pref--;\
        cipher_abilities[aes128_mapi]++;\
        cipher_votes[aes128_mapi] += pref;\
        pref--;\
        cipher_abilities[strong_mapi]++;\
        cipher_votes[strong_mapi] += pref;\
        pref--;\
    }

#endif //MOZILLA_PROJECTS_MTG_SMIMEUTIL_H
