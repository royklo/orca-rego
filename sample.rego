package authz

import rego.v1

default allow := false

# Allow admins to do anything.
allow if {
    "admin" in input.user.roles
}

allow if {
    input.method == "GET"
    startswith(input.path, "/public/")
    count(input.user.roles) > 0
}

deny_message := sprintf("user %v may not %v %v", [input.user.name, input.method, input.path]) if not allow
