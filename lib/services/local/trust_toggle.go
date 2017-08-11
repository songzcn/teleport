package local

import (
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
)

// TrustToggle is local implementation of TrustToggle service that uses
// a local backend.
type TrustToggle struct {
	backend.Backend
	services.Trust
}

// NewTrustToggleService returns new instance of
func NewTrustToggleService(backend backend.Backend, trust services.Trust) *TrustToggle {
	return &TrustToggle{
		Backend: backend,
		Trust:   trust,
	}
}

// ActivateCertAuthority moves a CertAuthority from the deactivated list to
// the normal list.
func (s *TrustToggle) ActivateCertAuthority(id services.CertAuthID) error {
	data, err := s.GetVal([]string{"authorities", "deactivated", string(id.Type)}, id.DomainName)
	if err != nil {
		return trace.BadParameter("can not activate CertAuthority which has not been deactivated: %v: %v", id, err)
	}

	certAuthority, err := services.GetCertAuthorityMarshaler().UnmarshalCertAuthority(data)
	if err != nil {
		return trace.Wrap(err)
	}

	err = s.UpsertCertAuthority(certAuthority)
	if err != nil {
		return trace.Wrap(err)
	}

	err = s.DeleteKey([]string{"authorities", "deactivated", string(id.Type)}, id.DomainName)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// DeactivateCertAuthority moves a CertAuthority from the normal list to
// the deactivated list.
func (s *TrustToggle) DeactivateCertAuthority(id services.CertAuthID) error {
	certAuthority, err := s.GetCertAuthority(id, true)
	if err != nil {
		return trace.BadParameter("can not deactivate CertAuthority which does not exist: %v: %v", id, err)
	}

	data, err := services.GetCertAuthorityMarshaler().MarshalCertAuthority(certAuthority)
	if err != nil {
		return trace.Wrap(err)
	}
	ttl := backend.TTL(s.Clock(), certAuthority.GetMetadata().Expires)

	err = s.UpsertVal([]string{"authorities", "deactivated", string(id.Type)}, id.DomainName, data, ttl)
	if err != nil {
		return trace.Wrap(err)
	}

	err = s.DeleteCertAuthority(id)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}
