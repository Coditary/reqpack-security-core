#include "rqp/security/sync_backend_registry.h"

void rqp_security_register_osv_sync_backend();
void rqp_security_register_gh_advisory_sync_backend();
void rqp_security_register_snyk_sync_backend();
void rqp_security_register_trivy_sync_backend();

void rqp_security_register_builtin_sync_backends() {
    rqp_security_register_osv_sync_backend();
#ifdef RQP_SECURITY_HAVE_BACKEND_GH_ADVISORY
    rqp_security_register_gh_advisory_sync_backend();
#endif
#ifdef RQP_SECURITY_HAVE_BACKEND_SNYK
    rqp_security_register_snyk_sync_backend();
#endif
#ifdef RQP_SECURITY_HAVE_BACKEND_TRIVY
    rqp_security_register_trivy_sync_backend();
#endif
}
