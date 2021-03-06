/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	. "gopkg.in/check.v1"
)

func TestRoleParsing(t *testing.T) { TestingT(t) }

type RoleSuite struct {
}

var _ = Suite(&RoleSuite{})
var _ = fmt.Printf

func (s *RoleSuite) SetUpSuite(c *C) {
	utils.InitLoggerForTests()
}

func (s *RoleSuite) TestRoleExtension(c *C) {
	type Spec struct {
		RoleSpecV2
		A string `json:"a"`
	}
	type ExtendedRole struct {
		Spec Spec `json:"spec"`
	}
	in := `{"kind": "role", "metadata": {"name": "name1"}, "spec": {"a": "b"}}`
	var role ExtendedRole
	err := utils.UnmarshalWithSchema(GetRoleSchema(V2, `"a": {"type": "string"}`), &role, []byte(in))
	c.Assert(err, IsNil)
	c.Assert(role.Spec.A, Equals, "b")

	// this is a bad type
	in = `{"kind": "role", "metadata": {"name": "name1"}, "spec": {"a": 12}}`
	err = utils.UnmarshalWithSchema(GetRoleSchema(V2, `"a": {"type": "string"}`), &role, []byte(in))
	c.Assert(err, NotNil)
}

func (s *RoleSuite) TestRoleParse(c *C) {
	testCases := []struct {
		in    string
		role  RoleV3
		error error
	}{
		// 0 - no input, should not parse
		{
			in:    ``,
			error: trace.BadParameter("empty input"),
		},
		// 1 - validation error, no name
		{
			in:    `{}`,
			error: trace.BadParameter("failed to validate: name: name is required"),
		},
		// 2 - validation error, no name
		{
			in:    `{"kind": "role"}`,
			error: trace.BadParameter("failed to validate: name: name is required"),
		},
		// 3 - role with no spec
		{
			in: `{"kind": "role", "version": "v3", "metadata": {"name": "name1"}, "spec": {}}`,
			role: RoleV3{
				Kind:    KindRole,
				Version: V3,
				Metadata: Metadata{
					Name:      "name1",
					Namespace: defaults.Namespace,
				},
				Spec: RoleSpecV3{},
			},
		},
		// 4 - full valid role
		{
			in: `{
		      "kind": "role",
		      "version": "v3",
		      "metadata": {"name": "name1"},
		      "spec": {
                 "options": {
                   "max_session_ttl": "20h"
                 },
                 "allow": {
                   "node_labels": {"a": "b"},
                   "namespaces": ["system", "default"],
                   "rules": [
                     {
                       "resources": ["role"],
                       "verbs": ["read", "write"]
                     }
                   ]
                 },
                 "deny": {
                   "logins": ["c"]
                 }
		      }
		    }`,
			role: RoleV3{
				Kind:    KindRole,
				Version: V3,
				Metadata: Metadata{
					Name:      "name1",
					Namespace: defaults.Namespace,
				},
				Spec: RoleSpecV3{
					Options: RoleOptions{
						MaxSessionTTL: NewDuration(20 * time.Hour),
					},
					Allow: RoleConditions{
						NodeLabels: map[string]string{"a": "b"},
						Namespaces: []string{"system", "default"},
						Rules: map[string][]string{
							"role": []string{ActionRead, ActionWrite},
						},
					},
					Deny: RoleConditions{
						Logins: []string{"c"},
					},
				},
			},
		},
	}
	for i, tc := range testCases {
		comment := Commentf("test case %v", i)

		role, err := UnmarshalRole([]byte(tc.in))
		if tc.error != nil {
			c.Assert(err, NotNil, comment)
		} else {
			c.Assert(err, IsNil, comment)
			c.Assert(*role, DeepEquals, tc.role, comment)

			out, err := json.Marshal(role)
			c.Assert(err, IsNil, comment)

			role2, err := UnmarshalRole(out)
			c.Assert(err, IsNil, comment)
			c.Assert(*role2, DeepEquals, tc.role, comment)
		}
	}
}

func (s *RoleSuite) TestCheckAccess(c *C) {
	type check struct {
		server    Server
		hasAccess bool
		login     string
	}
	serverA := &ServerV2{
		Metadata: Metadata{
			Name: "a",
		},
	}
	serverB := &ServerV2{
		Metadata: Metadata{
			Name:      "b",
			Namespace: defaults.Namespace,
			Labels:    map[string]string{"role": "worker", "status": "follower"},
		},
	}
	namespaceC := "namespace-c"
	serverC := &ServerV2{
		Metadata: Metadata{
			Name:      "c",
			Namespace: namespaceC,
			Labels:    map[string]string{"role": "db", "status": "follower"},
		},
	}
	testCases := []struct {
		name   string
		roles  []RoleV2
		checks []check
	}{
		{
			name:  "empty role set has access to nothing",
			roles: []RoleV2{},
			checks: []check{
				{server: serverA, login: "root", hasAccess: false},
				{server: serverB, login: "root", hasAccess: false},
				{server: serverC, login: "root", hasAccess: false},
			},
		},
		{
			name: "role is limited to default namespace",
			roles: []RoleV2{
				RoleV2{
					Metadata: Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: RoleSpecV2{
						MaxSessionTTL: Duration{20 * time.Hour},
						Logins:        []string{"admin"},
						NodeLabels:    map[string]string{Wildcard: Wildcard},
						Namespaces:    []string{defaults.Namespace},
					},
				},
			},
			checks: []check{
				{server: serverA, login: "root", hasAccess: false},
				{server: serverA, login: "admin", hasAccess: true},
				{server: serverB, login: "root", hasAccess: false},
				{server: serverB, login: "admin", hasAccess: true},
				{server: serverC, login: "root", hasAccess: false},
				{server: serverC, login: "admin", hasAccess: false},
			},
		},
		{
			name: "role is limited to labels in default namespace",
			roles: []RoleV2{
				RoleV2{
					Metadata: Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: RoleSpecV2{
						MaxSessionTTL: Duration{20 * time.Hour},
						Logins:        []string{"admin"},
						NodeLabels:    map[string]string{"role": "worker"},
						Namespaces:    []string{defaults.Namespace},
					},
				},
			},
			checks: []check{
				{server: serverA, login: "root", hasAccess: false},
				{server: serverA, login: "admin", hasAccess: false},
				{server: serverB, login: "root", hasAccess: false},
				{server: serverB, login: "admin", hasAccess: true},
				{server: serverC, login: "root", hasAccess: false},
				{server: serverC, login: "admin", hasAccess: false},
			},
		},
		{
			name: "one role is more permissive than another",
			roles: []RoleV2{
				RoleV2{
					Metadata: Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: RoleSpecV2{
						MaxSessionTTL: Duration{20 * time.Hour},
						Logins:        []string{"admin"},
						NodeLabels:    map[string]string{"role": "worker"},
						Namespaces:    []string{defaults.Namespace},
					},
				},
				RoleV2{
					Metadata: Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: RoleSpecV2{
						MaxSessionTTL: Duration{20 * time.Hour},
						Logins:        []string{"root", "admin"},
						NodeLabels:    map[string]string{Wildcard: Wildcard},
						Namespaces:    []string{Wildcard},
					},
				},
			},
			checks: []check{
				{server: serverA, login: "root", hasAccess: true},
				{server: serverA, login: "admin", hasAccess: true},
				{server: serverB, login: "root", hasAccess: true},
				{server: serverB, login: "admin", hasAccess: true},
				{server: serverC, login: "root", hasAccess: true},
				{server: serverC, login: "admin", hasAccess: true},
			},
		},
	}
	for i, tc := range testCases {

		var set RoleSet
		for i := range tc.roles {
			set = append(set, tc.roles[i].V3())
		}
		for j, check := range tc.checks {
			comment := Commentf("test case %v '%v', check %v", i, tc.name, j)
			result := set.CheckAccessToServer(check.login, check.server)
			if check.hasAccess {
				c.Assert(result, IsNil, comment)
			} else {
				c.Assert(trace.IsAccessDenied(result), Equals, true, comment)
			}

		}
	}
}

func (s *RoleSuite) TestCheckResourceAccess(c *C) {
	type check struct {
		hasAccess bool
		action    string
		namespace string
		resource  string
	}
	testCases := []struct {
		name   string
		roles  []RoleV3
		checks []check
	}{
		{
			name:  "0 - empty role set has access to nothing",
			roles: []RoleV3{},
			checks: []check{
				{resource: KindUser, action: ActionWrite, namespace: defaults.Namespace, hasAccess: false},
			},
		},
		{
			name: "1 - user can read sessions in default namespace",
			roles: []RoleV3{
				RoleV3{
					Metadata: Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: RoleSpecV3{
						Allow: RoleConditions{
							Namespaces: []string{defaults.Namespace},
							SystemResources: map[string][]string{
								KindSession: []string{ActionRead},
							},
						},
					},
				},
			},
			checks: []check{
				{resource: KindSession, action: ActionRead, namespace: defaults.Namespace, hasAccess: true},
				{resource: KindSession, action: ActionWrite, namespace: defaults.Namespace, hasAccess: false},
			},
		},
		{
			name: "1 - user can read sessions in system namespace and write stuff in default namespace",
			roles: []RoleV3{
				RoleV3{
					Metadata: Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: RoleSpecV3{
						Allow: RoleConditions{
							Namespaces: []string{"system"},
							SystemResources: map[string][]string{
								KindSession: []string{ActionRead},
							},
						},
					},
				},
				RoleV3{
					Metadata: Metadata{
						Name:      "name2",
						Namespace: defaults.Namespace,
					},
					Spec: RoleSpecV3{
						Allow: RoleConditions{
							Namespaces: []string{defaults.Namespace},
							SystemResources: map[string][]string{
								KindSession: []string{ActionWrite, ActionRead},
							},
						},
					},
				},
			},
			checks: []check{
				{resource: KindSession, action: ActionRead, namespace: defaults.Namespace, hasAccess: true},
				{resource: KindSession, action: ActionWrite, namespace: defaults.Namespace, hasAccess: true},
				{resource: KindSession, action: ActionWrite, namespace: "system", hasAccess: false},
				{resource: KindRole, action: ActionRead, namespace: defaults.Namespace, hasAccess: false},
			},
		},
		{
			name: "3 - deny rules override allow rules",
			roles: []RoleV3{
				RoleV3{
					Metadata: Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: RoleSpecV3{
						Deny: RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: map[string][]string{
								KindSession: []string{ActionWrite},
							},
						},
						Allow: RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: map[string][]string{
								KindSession: []string{ActionWrite},
							},
						},
					},
				},
			},
			checks: []check{
				{resource: KindSession, action: ActionWrite, namespace: defaults.Namespace, hasAccess: false},
			},
		},
		{
			name: "4 - rules override system resources",
			roles: []RoleV3{
				RoleV3{
					Metadata: Metadata{
						Name:      "name1",
						Namespace: defaults.Namespace,
					},
					Spec: RoleSpecV3{
						Allow: RoleConditions{
							Namespaces: []string{defaults.Namespace},
							Rules: map[string][]string{
								KindSession: []string{ActionWrite},
							},
							SystemResources: map[string][]string{
								KindSession: []string{ActionRead},
							},
						},
					},
				},
			},
			checks: []check{
				{resource: KindSession, action: ActionWrite, namespace: defaults.Namespace, hasAccess: true},
			},
		},
	}
	for i, tc := range testCases {
		var set RoleSet
		for i := range tc.roles {
			set = append(set, &tc.roles[i])
		}
		for j, check := range tc.checks {
			comment := Commentf("test case %v '%v', check %v", i, tc.name, j)
			result := set.CheckAccessToRuleOrResource(check.namespace, check.resource, check.action)
			if check.hasAccess {
				c.Assert(result, IsNil, comment)
			} else {
				c.Assert(trace.IsAccessDenied(result), Equals, true, comment)
			}

		}
	}
}

func (s *RoleSuite) TestApplyTraits(c *C) {
	var tests = []struct {
		inTraits  map[string][]string
		inLogins  []string
		outLogins []string
	}{
		// 0 - substitute in allow rule
		{
			map[string][]string{
				"foo": []string{"bar"},
			},
			[]string{`{{external.foo}}`, "root"},
			[]string{"bar", "root"},
		},
		// 1 - substitute in deny rule
		{
			map[string][]string{
				"foo": []string{"bar"},
			},
			[]string{`{{external.foo}}`},
			[]string{"bar"},
		},
		// 2 - no variable in logins
		{
			map[string][]string{
				"foo": []string{"bar"},
			},
			[]string{"root"},
			[]string{"root"},
		},
		// 3 - invalid variable in logins gets passed along
		{
			map[string][]string{
				"foo": []string{"bar"},
			},
			[]string{`external.foo}}`},
			[]string{`external.foo}}`},
		},
		// 4 - variable in logins, none in traits
		{
			map[string][]string{
				"foo": []string{"bar"},
			},
			[]string{`{{internal.bar}}`, "root"},
			[]string{"root"},
		},
		// 5 - multiple variables in traits
		{
			map[string][]string{
				"logins": []string{"bar", "baz"},
			},
			[]string{`{{internal.logins}}`, "root"},
			[]string{"bar", "baz", "root"},
		},
		// 6 - deduplicate
		{
			map[string][]string{
				"foo": []string{"bar"},
			},
			[]string{`{{external.foo}}`, "bar"},
			[]string{"bar"},
		},
	}

	for i, tt := range tests {
		comment := Commentf("Test %v", i)

		role := &RoleV3{
			Kind:    KindRole,
			Version: V3,
			Metadata: Metadata{
				Name:      "name1",
				Namespace: defaults.Namespace,
			},
			Spec: RoleSpecV3{
				Allow: RoleConditions{
					Logins: tt.inLogins,
				},
			},
		}
		outRole := role.ApplyTraits(tt.inTraits)
		c.Assert(outRole.GetLogins(Allow), DeepEquals, tt.outLogins, comment)
	}
}

func (s *RoleSuite) TestCheckAndSetDefaults(c *C) {
	var tests = []struct {
		inLogins []string
		outError bool
	}{
		// 0 - invalid syntax
		{
			[]string{"{{foo"},
			true,
		},
		// 1 - invalid syntax
		{
			[]string{"bar}}"},
			true,
		},
		// 2 - valid syntax
		{
			[]string{"{{foo.bar}}"},
			false,
		},
	}

	for i, tt := range tests {
		comment := Commentf("Test %v", i)

		role := &RoleV3{
			Kind:    KindRole,
			Version: V3,
			Metadata: Metadata{
				Name:      "name1",
				Namespace: defaults.Namespace,
			},
			Spec: RoleSpecV3{
				Allow: RoleConditions{
					Logins: tt.inLogins,
				},
			},
		}
		if tt.outError {
			c.Assert(role.CheckAndSetDefaults(), NotNil, comment)
		} else {
			c.Assert(role.CheckAndSetDefaults(), IsNil, comment)
		}
	}

}
