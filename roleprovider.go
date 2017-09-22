package kubetoken

import (
	"fmt"
        "log"

	ldap "gopkg.in/ldap.v2"
)

// ADRoleProvider speaks Active Directory flavoured LDAP to retrieve the
// roles available to a specific user.
type ADRoleProvider struct {
	LDAPCreds
}

func (r *ADRoleProvider) FetchRolesForUser(userdn string) ([]string, error) {
	return fetchRolesForUser(&r.LDAPCreds, userdn)
}

func fetchRolesForUser(creds *LDAPCreds, userdn string) ([]string, error) {
	conn, err := creds.Bind()
	if err != nil {
		return nil, err
	}
	//defer conn.Close()
log.Println("bound")
	// find all the kube- roles
	filter := fmt.Sprintf("(&(objectClass=group)(member=%s))", userdn)

	kubeRoles := ldap.NewSearchRequest(
		SearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"cn"},
		nil,
	)
	sr, err := conn.Search(kubeRoles)
	if err != nil {
		return nil, err
	}

	var roles []string
	for _, e := range sr.Entries {
                log.Println("roles", e)
		role := e.GetAttributeValue("cn")
		roles = append(roles, role)
	}
	return roles, nil
}
