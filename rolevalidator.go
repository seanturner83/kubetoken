package kubetoken

import (
	"fmt"
	"strings"

	ldap "gopkg.in/ldap.v2"
)

// LDAPConn represents a LDAP connection that can handle search requests.
type LDAPConn interface {

	// Search performs a given search request.
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)

	// Close closes the connection and frees any associated requets.
	Close() // yes, ldap.v2 gets this wrong
}

// ADRoleValidater validates a user is permitted to assume a role
// as specified in Active Directory flavoured LDAP.
type ADRoleValidater struct {
	Bind func() (LDAPConn, error)
}

func (r *ADRoleValidater) ValidateRoleForUser(user, userdn, roledn string) error {
	filter := fmt.Sprintf("(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=%s))", roledn)
	kubeRoles := ldap.NewSearchRequest(
		userdn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"samaccountname"},
		nil,
	)
	conn, err := r.Bind()
	if err != nil {
		return err
	}
	defer conn.Close()

	sr, err := conn.Search(kubeRoles)
	if err != nil {
		return err
	}
	switch len(sr.Entries) {
	case 0:
		return fmt.Errorf("%s is not a member of %s", userdn, roledn)
	case 1:
		usercn := sr.Entries[0].GetAttributeValue("sAMAccountName")
		if strings.ToLower(user) != strings.ToLower(usercn) {
			return fmt.Errorf("%q is not a member of %q; search returned %q", user, roledn, usercn)
		}
		return nil
	default:
		return fmt.Errorf("got %d entries for query %s: %s", len(sr.Entries), filter, sr.Entries)
	}

}
