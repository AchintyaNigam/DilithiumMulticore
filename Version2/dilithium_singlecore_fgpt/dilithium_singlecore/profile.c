#include "profile.h"
#include <string.h>

keygen_profile_t kg_prof;
sign_profile_t sign_prof;
verify_profile_t ver_prof;

void profile_reset(void) {
    memset(&kg_prof, 0, sizeof(kg_prof));
    memset(&sign_prof, 0, sizeof(sign_prof));
    memset(&ver_prof, 0, sizeof(ver_prof));
}