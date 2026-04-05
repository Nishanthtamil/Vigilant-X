/**
 * intentional_vulns/use_after_free.cpp
 * ─────────────────────────────────────
 * Deliberate use-after-free for Vigilant-X validation.
 * BUG: Session pointer is freed in logout(), then dereferenced
 *      in audit_log() which still holds the dangling pointer.
 */
#include <cstdlib>
#include <cstring>
#include <cstdio>

struct Session {
    int user_id;
    char username[32];
    char token[64];
    bool is_admin;
};

Session* create_session(int uid, const char* name) {
    Session* s = (Session*)malloc(sizeof(Session));
    if (!s) return nullptr;
    s->user_id = uid;
    strncpy(s->username, name, sizeof(s->username) - 1);
    s->username[31] = '\0';
    snprintf(s->token, sizeof(s->token), "tok_%d_%s", uid, name);
    s->is_admin = false;
    return s;
}

void logout(Session* s) {
    printf("Logging out user %d\n", s->user_id);
    free(s);  // Session memory freed here
}

void audit_log(Session* s) {
    // BUG: use-after-free — s was already freed by logout()
    printf("AUDIT: user=%s (id=%d) admin=%d token=%s\n",
           s->username, s->user_id, s->is_admin, s->token);
}

int main() {
    Session* sess = create_session(42, "alice");
    logout(sess);

    // Trigger UAF: allocate something to corrupt freed memory
    char* noise = (char*)malloc(sizeof(Session));
    memset(noise, 0xFF, sizeof(Session));

    audit_log(sess);  // Dangling pointer access
    free(noise);
    return 0;
}
