"""Streamlit Admin UI for the Access Control Platform.

One console to drive the whole system (docs/DESIGN.md §11, §14):
  * authenticate a global identity and select/switch the active tenant
  * manage tenants, global users, members, org-units
  * manage roles (grants + inheritance), the permission catalog, and ABAC policies
  * a **decision simulator** that calls the PDP /check and explains the verdict
  * an audit-log viewer

The UI holds no business logic — every decision and change goes through the
Auth and Authz service APIs, exactly like any other client.
"""
from __future__ import annotations

import json
import os
import sys

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ui import api  # noqa: E402
from ui.api import ApiError  # noqa: E402

st.set_page_config(page_title="Access Control Admin", page_icon="🔐", layout="wide")

S = st.session_state
S.setdefault("identity_token", None)
S.setdefault("access_token", None)
S.setdefault("email", None)
S.setdefault("user_id", None)
S.setdefault("memberships", [])
S.setdefault("tenant_id", None)
S.setdefault("tenant_name", None)
S.setdefault("roles", [])


# =========================================================================
# Auth helpers
# =========================================================================
def do_login(email: str, password: str) -> None:
    data = api.auth_post("/auth/login", json={"email": email, "password": password})
    S.identity_token = data["identity_token"]
    S.email = data["email"]
    S.user_id = data["user_id"]
    S.memberships = data["memberships"]
    S.access_token = None
    S.tenant_id = None
    S.tenant_name = None
    S.roles = []
    # Auto-select if exactly one active membership.
    active = [m for m in S.memberships if m["status"] == "active"]
    if len(active) == 1:
        select_tenant(active[0]["tenant_id"])


def select_tenant(tenant_id: str) -> None:
    data = api.auth_post("/auth/select-tenant", token=S.identity_token,
                         json={"tenant_id": tenant_id})
    S.access_token = data["access_token"]
    S.tenant_id = str(data["tenant_id"])
    S.roles = data["roles"]
    S.tenant_name = next(
        (m["tenant_name"] for m in S.memberships if str(m["tenant_id"]) == S.tenant_id),
        S.tenant_id,
    )


def logout() -> None:
    for k in ("identity_token", "access_token", "email", "user_id",
              "memberships", "tenant_id", "tenant_name", "roles"):
        S[k] = None if k != "memberships" and k != "roles" else []


def require_tenant() -> bool:
    if not S.access_token:
        st.info("Select an active tenant in the sidebar to manage roles, policies, "
                "simulate decisions, or view the audit log.")
        return False
    return True


# =========================================================================
# Sidebar — identity & tenant context
# =========================================================================
def sidebar() -> None:
    st.sidebar.title("🔐 Access Control")

    if not S.identity_token:
        st.sidebar.subheader("Sign in")
        with st.sidebar.form("login"):
            email = st.text_input("Email", value="alice@acme.com")
            password = st.text_input("Password", value="password", type="password")
            if st.form_submit_button("Log in", use_container_width=True):
                try:
                    do_login(email, password)
                    st.rerun()
                except ApiError as e:
                    st.sidebar.error(f"Login failed: {e.detail}")
        st.sidebar.caption("Demo users (password `password`): alice/bob/carol/"
                           "dave/peggy@acme.com, frank@globex.com")
        return

    st.sidebar.success(f"**{S.email}**")
    options = {f"{m['tenant_name']} · {m['status']}": str(m["tenant_id"])
               for m in S.memberships}
    if options:
        labels = list(options)
        current = next((l for l, tid in options.items() if tid == S.tenant_id), None)
        idx = labels.index(current) if current else 0
        chosen = st.sidebar.selectbox("Active tenant", labels, index=idx)
        if st.sidebar.button("Switch to this tenant", use_container_width=True):
            try:
                select_tenant(options[chosen])
                st.rerun()
            except ApiError as e:
                st.sidebar.error(f"{e.detail}")
    else:
        st.sidebar.warning("No tenant memberships. You can still create tenants/users.")

    if S.tenant_id:
        st.sidebar.caption(f"Acting in **{S.tenant_name}**")
        st.sidebar.caption(f"Roles: {', '.join(S.roles) or '—'}")

    if st.sidebar.button("Log out", use_container_width=True):
        logout()
        st.rerun()


# =========================================================================
# Lookup helpers
# =========================================================================
def perm_map() -> dict[str, dict]:
    """key -> permission record."""
    return {p["key"]: p for p in api.authz_get("/permissions", token=S.access_token)}


def role_list() -> list[dict]:
    return api.authz_get("/roles", token=S.access_token)


# =========================================================================
# Pages
# =========================================================================
def page_overview() -> None:
    st.header("Overview")
    st.markdown(
        "This console drives a multi-tenant **RBAC + ABAC** access-control system. "
        "Authentication is global; authorization is centralized in a Policy Decision "
        "Point (PDP) that every microservice consults through a shared enforcement library."
    )
    c1, c2, c3 = st.columns(3)
    c1.metric("Signed in as", S.email or "—")
    c2.metric("Active tenant", S.tenant_name or "— (select one)")
    c3.metric("Roles in tenant", len(S.roles))
    st.subheader("Your memberships")
    if S.memberships:
        st.dataframe(pd.DataFrame(S.memberships), use_container_width=True, hide_index=True)
    else:
        st.write("—")


def page_tenants_users() -> None:
    st.header("Tenants & Users")
    tok = S.access_token or S.identity_token

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Tenants")
        try:
            tenants = api.auth_get("/tenants", token=tok)
            st.dataframe(pd.DataFrame(tenants), use_container_width=True, hide_index=True)
        except ApiError as e:
            st.error(e.detail)
        with st.form("new_tenant"):
            name = st.text_input("New tenant name")
            tier = st.selectbox("Tier", ["pooled", "enterprise"])
            if st.form_submit_button("Create tenant"):
                try:
                    api.auth_post("/tenants", token=tok, json={"name": name, "tier": tier})
                    st.success(f"Created {name}")
                    st.rerun()
                except ApiError as e:
                    st.error(e.detail)

    with col2:
        st.subheader("Global users")
        try:
            users = api.auth_get("/users", token=tok)
            st.dataframe(pd.DataFrame(users), use_container_width=True, hide_index=True)
        except ApiError as e:
            st.error(e.detail)
        with st.form("new_user"):
            email = st.text_input("New user email")
            pw = st.text_input("Password", type="password")
            if st.form_submit_button("Create user"):
                try:
                    api.auth_post("/users", token=tok, json={"email": email, "password": pw})
                    st.success(f"Created {email}")
                    st.rerun()
                except ApiError as e:
                    st.error(e.detail)


def page_members_roles() -> None:
    st.header("Members & Roles")
    if not require_tenant():
        return
    tid = S.tenant_id
    tok = S.access_token

    # Org units
    st.subheader("Org units")
    try:
        units = api.auth_get(f"/tenants/{tid}/org-units", token=tok)
        st.dataframe(pd.DataFrame(units) if units else pd.DataFrame(columns=["name"]),
                     use_container_width=True, hide_index=True)
    except ApiError as e:
        st.error(e.detail)
        units = []
    with st.form("new_ou"):
        ou_name = st.text_input("New org-unit name")
        if st.form_submit_button("Create org-unit"):
            try:
                api.auth_post(f"/tenants/{tid}/org-units", token=tok, json={"name": ou_name})
                st.rerun()
            except ApiError as e:
                st.error(e.detail)

    st.divider()
    st.subheader("Members")
    try:
        members = api.auth_get(f"/tenants/{tid}/members", token=tok)
    except ApiError as e:
        st.error(e.detail)
        members = []
    if members:
        st.dataframe(
            pd.DataFrame([{"email": m["email"], "status": m["status"],
                           "roles": ", ".join(m["roles"]) or "—"} for m in members]),
            use_container_width=True, hide_index=True)

    # Add member
    with st.expander("Add a member to this tenant"):
        users = api.auth_get("/users", token=tok)
        member_ids = {str(m["user_id"]) for m in members}
        candidates = {u["email"]: str(u["id"]) for u in users if str(u["id"]) not in member_ids}
        ou_opts = {"(none)": None} | {u["name"]: str(u["id"]) for u in units}
        with st.form("add_member"):
            who = st.selectbox("User", list(candidates) or ["— no users available —"])
            ou = st.selectbox("Org unit", list(ou_opts))
            if st.form_submit_button("Add member") and who in candidates:
                try:
                    api.auth_post(f"/tenants/{tid}/members", token=tok,
                                  json={"user_id": candidates[who], "org_unit_id": ou_opts[ou]})
                    st.rerun()
                except ApiError as e:
                    st.error(e.detail)

    # Assign / unassign roles
    with st.expander("Assign or remove a role"):
        roles = role_list()
        role_by_name = {r["name"]: str(r["id"]) for r in roles}
        member_by_email = {m["email"]: m for m in members}
        if member_by_email and role_by_name:
            colA, colB = st.columns(2)
            with colA.form("assign_role"):
                st.caption("Assign")
                m_email = st.selectbox("Member", list(member_by_email), key="ar_m")
                r_name = st.selectbox("Role", list(role_by_name), key="ar_r")
                if st.form_submit_button("Assign role"):
                    mid = member_by_email[m_email]["membership_id"]
                    try:
                        api.auth_post(f"/memberships/{mid}/roles", token=tok,
                                      json={"role_id": role_by_name[r_name]})
                        st.rerun()
                    except ApiError as e:
                        st.error(e.detail)
            with colB.form("unassign_role"):
                st.caption("Remove")
                m_email2 = st.selectbox("Member", list(member_by_email), key="ur_m")
                r_name2 = st.selectbox("Role", list(role_by_name), key="ur_r")
                if st.form_submit_button("Remove role"):
                    mid = member_by_email[m_email2]["membership_id"]
                    try:
                        api.auth_delete(f"/memberships/{mid}/roles/{role_by_name[r_name2]}",
                                        token=tok)
                        st.rerun()
                    except ApiError as e:
                        st.error(e.detail)


def page_permissions() -> None:
    st.header("Permission catalog (global)")
    if not require_tenant():
        return
    try:
        perms = api.authz_get("/permissions", token=S.access_token)
        st.dataframe(pd.DataFrame(perms)[["key", "service", "resource", "action", "description"]]
                     if perms else pd.DataFrame(columns=["key"]),
                     use_container_width=True, hide_index=True)
    except ApiError as e:
        st.error(e.detail)
    with st.form("new_perm"):
        st.caption("Register a new (service, resource, action) permission")
        c = st.columns(4)
        service = c[0].text_input("service")
        resource = c[1].text_input("resource")
        action = c[2].text_input("action")
        desc = c[3].text_input("description")
        if st.form_submit_button("Register permission"):
            try:
                api.authz_post("/permissions", token=S.access_token,
                               json={"service": service, "resource": resource,
                                     "action": action, "description": desc})
                st.rerun()
            except ApiError as e:
                st.error(e.detail)


def page_roles_policies() -> None:
    st.header("Roles & Policies")
    if not require_tenant():
        return
    tok = S.access_token
    roles = role_list()
    perms = perm_map()

    st.subheader("Roles")
    if roles:
        rows = []
        for r in roles:
            detail = api.authz_get(f"/roles/{r['id']}", token=tok)
            rows.append({"name": r["name"], "description": r["description"],
                         "inherits": ", ".join(detail["inherits"]) or "—",
                         "effective permissions": ", ".join(detail["permissions"]) or "—"})
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with st.expander("Create role / grant permission / add inheritance"):
        with st.form("new_role"):
            st.caption("New role")
            rn = st.text_input("Role name")
            rd = st.text_input("Description")
            if st.form_submit_button("Create role"):
                try:
                    api.authz_post("/roles", token=tok, json={"name": rn, "description": rd})
                    st.rerun()
                except ApiError as e:
                    st.error(e.detail)

        role_by_name = {r["name"]: str(r["id"]) for r in roles}
        if role_by_name and perms:
            colA, colB = st.columns(2)
            with colA.form("grant_perm"):
                st.caption("Grant a permission to a role")
                gr = st.selectbox("Role", list(role_by_name), key="g_role")
                gp = st.selectbox("Permission", list(perms), key="g_perm")
                if st.form_submit_button("Grant"):
                    try:
                        api.authz_post(f"/roles/{role_by_name[gr]}/permissions", token=tok,
                                       json={"permission_id": perms[gp]["id"]})
                        st.rerun()
                    except ApiError as e:
                        st.error(e.detail)
            with colB.form("add_child"):
                st.caption("Make a role inherit another (parent → child)")
                parent = st.selectbox("Parent role", list(role_by_name), key="h_parent")
                child = st.selectbox("Inherits (child)", list(role_by_name), key="h_child")
                if st.form_submit_button("Add inheritance"):
                    try:
                        api.authz_post(f"/roles/{role_by_name[parent]}/children", token=tok,
                                       json={"child_role_id": role_by_name[child]})
                        st.rerun()
                    except ApiError as e:
                        st.error(e.detail)

    st.divider()
    st.subheader("ABAC policies")
    try:
        policies = api.authz_get("/policies", token=tok)
    except ApiError as e:
        st.error(e.detail)
        policies = []
    id_to_key = {p["id"]: k for k, p in perms.items()}
    if policies:
        st.dataframe(pd.DataFrame([{
            "name": p["name"], "permission": id_to_key.get(p["permission_id"], p["permission_id"]),
            "effect": p["effect"], "enabled": p["enabled"], "version": p["version"],
            "condition": json.dumps(p["condition"]),
        } for p in policies]), use_container_width=True, hide_index=True)

    with st.expander("Create a policy"):
        st.caption("Condition is the JSON DSL — e.g. "
                   "`{\"all\": [{\"lt\": [\"resource.amount\", 10000]}]}`")
        with st.form("new_policy"):
            pname = st.text_input("Policy name")
            ptarget = st.selectbox("Attach to permission", list(perms))
            peffect = st.selectbox("Effect", ["allow", "deny"])
            pcond = st.text_area("Condition (JSON)", value='{"all": []}', height=120)
            if st.form_submit_button("Create policy"):
                try:
                    condition = json.loads(pcond)
                    api.authz_post("/policies", token=tok, json={
                        "permission_id": perms[ptarget]["id"], "name": pname,
                        "condition": condition, "effect": peffect})
                    st.rerun()
                except json.JSONDecodeError as e:
                    st.error(f"Invalid JSON: {e}")
                except ApiError as e:
                    st.error(e.detail)

    if policies:
        with st.expander("Enable / disable / delete a policy"):
            pol_by_name = {p["name"]: p for p in policies}
            sel = st.selectbox("Policy", list(pol_by_name))
            c1, c2, c3 = st.columns(3)
            if c1.button("Enable"):
                api.authz_put(f"/policies/{pol_by_name[sel]['id']}", token=tok,
                              json={"enabled": True}); st.rerun()
            if c2.button("Disable"):
                api.authz_put(f"/policies/{pol_by_name[sel]['id']}", token=tok,
                              json={"enabled": False}); st.rerun()
            if c3.button("Delete", type="primary"):
                api.authz_delete(f"/policies/{pol_by_name[sel]['id']}", token=tok); st.rerun()


def page_simulator() -> None:
    st.header("Decision Simulator")
    if not require_tenant():
        return
    tok = S.access_token
    st.caption("Replays a `POST /check` against the PDP and explains the verdict — "
               "test access **before** rolling out a change.")

    members = api.auth_get(f"/tenants/{S.tenant_id}/members", token=tok)
    perms = perm_map()

    member_by_email = {m["email"]: m for m in members}
    colL, colR = st.columns(2)
    with colL:
        who = st.selectbox("Subject (member)", list(member_by_email) or ["—"])
        action = st.selectbox("Action", list(perms))
        resource_txt = st.text_area(
            "Resource attributes (JSON)",
            value='{\n  "amount": 5000,\n  "org_unit_id": "",\n  "created_by": ""\n}',
            height=160)
    subject = {}
    if who in member_by_email:
        m = member_by_email[who]
        subject = {"user_id": str(m["user_id"]), "tenant_id": S.tenant_id,
                   "roles": m["roles"], "org_unit_id": str(m["org_unit_id"]) if m["org_unit_id"] else None}
    with colR:
        st.caption("Resolved subject sent to the PDP")
        st.json(subject)

    if st.button("Run check", type="primary"):
        try:
            resource = json.loads(resource_txt)
        except json.JSONDecodeError as e:
            st.error(f"Invalid resource JSON: {e}")
            return
        try:
            result = api.authz_post("/check", token=tok, json={
                "subject": subject, "action": action,
                "resource": resource, "environment": {}})
        except ApiError as e:
            st.error(e.detail)
            return
        if result["decision"] == "allow":
            st.success(f"ALLOW — reason: `{result['reason']}`")
        else:
            st.error(f"DENY — reason: `{result['reason']}`")
        st.json(result)


def page_audit() -> None:
    st.header("Audit log")
    if not require_tenant():
        return
    limit = st.slider("Rows", 10, 500, 100, step=10)
    try:
        rows = api.authz_get(f"/audit?limit={limit}", token=S.access_token)
    except ApiError as e:
        st.error(e.detail)
        return
    if not rows:
        st.write("No decisions recorded yet — run the simulator or hit a service.")
        return
    df = pd.DataFrame([{
        "time": r["created_at"], "action": r["action"], "decision": r["decision"],
        "reason": r["reason"], "actor": r["actor_user_id"],
    } for r in rows])
    st.dataframe(df, use_container_width=True, hide_index=True)


# =========================================================================
# Router
# =========================================================================
PAGES = {
    "Overview": page_overview,
    "Tenants & Users": page_tenants_users,
    "Members & Roles": page_members_roles,
    "Permissions": page_permissions,
    "Roles & Policies": page_roles_policies,
    "Decision Simulator": page_simulator,
    "Audit Log": page_audit,
}


def main() -> None:
    sidebar()
    if not S.identity_token:
        st.title("Access Control Admin")
        st.info("Please sign in using the sidebar.")
        return
    choice = st.sidebar.radio("Page", list(PAGES))
    try:
        PAGES[choice]()
    except ApiError as e:
        st.error(f"API error ({e.status}): {e.detail}")


main()
