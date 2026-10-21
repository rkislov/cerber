// SPDX-License-Identifier: Apache-2.0
package agent

import "golang.org/x/sys/windows"

func Privilege() string {
	token := windows.GetCurrentProcessToken()
	user, e := token.GetTokenUser()
	if e == nil && user.User.Sid.String() == "S-1-5-18" {
		return "system"
	}
	if token.IsElevated() {
		return "administrator"
	}
	return "unprivileged"
}
