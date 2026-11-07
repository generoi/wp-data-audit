package audit

import (
	"cmp"
	"fmt"
	"strings"
)

// access: who reaches the site's code or server outside WordPress. GitHub:
// outside collaborators, and deploy keys with write access. Kinsta: company
// users who aren't current staff (they reach every site, so the flag is the
// same on each), site users from outside the staff and client domains, and
// extra SFTP accounts. Flagged until accepted, so a new one stands out.
func (c *checker) access() {
	a := c.in.Facts.Access
	for _, e := range a.Errors {
		c.problem("%s", e)
	}
	if g := a.GitHub; g != nil {
		for _, u := range g.Outside {
			c.flag(Flag{ID: "collaborator:" + idPart(u.Login) + ":" + idPart(u.Permission), Severity: Review, Kind: KindCollaborator,
				Message: "outside collaborator on the GitHub repo (not in the organisation)", Untrusted: u.Login + " (" + u.Permission + ")"})
		}
		for _, k := range g.Keys {
			if k.ReadOnly {
				continue
			}
			c.flag(Flag{ID: fmt.Sprintf("deploy-key:%d", k.ID), Severity: Review, Kind: KindDeployKey,
				Message: "deploy key with write access to the GitHub repo", Untrusted: k.Title + " (added " + k.Created + ", last used " + cmp.Or(k.LastUsed, "never") + ")"})
		}
	}
	if k := a.Kinsta; k != nil {
		var client []string
		if c.in.Repo != nil {
			client = c.in.Repo.ClientDomains
		}
		for _, u := range k.Users {
			email := strings.ToLower(u.Email)
			staffDomain := domainIn(email, c.p.StaffDomains)
			var why string
			switch {
			case staffDomain && len(c.staff) > 0 && !c.staff[email]:
				why = "Kinsta access for a staff-domain address not on the staff list (a leaver?)"
			case staffDomain:
				continue
			case u.Scope == "company":
				why = "company-level Kinsta access (every site) from outside the staff domains"
			case domainIn(email, client):
				continue
			default:
				why = "Kinsta access to this site from outside the staff and client domains"
			}
			c.flag(Flag{ID: "kinsta-user:" + idPart(email) + ":" + idPart(u.Role), Severity: Review, Kind: KindKinstaUser,
				Message: why, Untrusted: u.Email + " (" + u.Role + ")"})
		}
		for _, s := range k.SFTP {
			state := "active"
			if !s.Active {
				state = "inactive"
			}
			c.flag(Flag{ID: "sftp:" + idPart(s.Env) + ":" + idPart(s.Username) + ":" + idPart(s.Permission), Severity: Review, Kind: KindSFTP,
				Message: "extra SFTP account on Kinsta", Untrusted: fmt.Sprintf("%s on %s, %s access to %s, %s", s.Username, s.Env, s.Permission, s.Root, state)})
		}
	} else {
		c.info("Kinsta users and SFTP accounts not checked: no Kinsta access from here (foreman checks them)")
	}
	if a.GitHub == nil {
		c.info("GitHub collaborators and deploy keys not checked")
	}
}
