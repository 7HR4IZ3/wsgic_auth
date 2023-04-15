# from wsgic.backend.cap import anonymous, roles
# from wsgic.routing import Routes, Router
# from wsgic.backend.bottle import static_file
# from .views import AuthView#,login, blogin, dlogin# MainView, AdminView

# routes = Routes(start="{", end="}", sep="::")
# router = Router()

# # with routes.use(MainView()) as routes:
# # 	routes.get("/", "index", name="auth-index"),
# # 	routes.get("status", "user_is_anonymous", name="status"),
# # 	routes.get("my_role", "current_user_role", name="my-role"),
# # 	routes.get("restricted", "restricted_download"),
# # 	routes.get("me", "me", name="me"),

# with routes.use(AuthView()) as routes:
# 	routes.add("login", "login", ["GET", "POST"], name="auth_login")
# 	routes.get("status", "status")
# 	routes.get("details", "details")

# 	routes.add("generate", "generate")

# 	routes.add("logout", "logout", ["GET", "POST"], name="auth_logout")

# 	routes.post("register", "register", name="auth_register")
# 	routes.get("validate/{code::int}", "validate", name="auth_validate")
# 	routes.get("reset_password", "send_password_reset_email", name="auth_password_reset")
# 	routes.post("change_password", "change_password", name="auth_change_pass")
# 	routes.get("change_password/{code::int}", "change_password_validate", name="auth_change_pass_validate")

# # with routes.use(AdminView()) as routes:
# # 	with routes.group("admin") as routes:
# # 		routes.get("/", "index", "admin"),
# # 		routes.post("/create_user", "create_user", name="new-user"),
# # 		routes.post("/delete_user", "delete_user", name="delete-user"),
# # 		routes.post("/create_role", "create_role", name="new-role"),
# # 		routes.post("/delete_role", "delete_role", name="delete-role")

# # routes.add("/baslogin", login)

# router.routes = routes