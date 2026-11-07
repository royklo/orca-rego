package authz

import rego.v1

# Admins may do anything.
allow if "admin" in input.user.roles

# Everyone may read public paths.
allow if {
    input.method == "GET"
    startswith(input.path, "/public/")
}

deny contains msg if {
    not allow
    msg := sprintf("%s may not %s", [input.user.name, input.path])
}

max_sessions := 5
