from wsgic.scripts import script
from wsgic.services import service

from .models import GroupsUsers

authorizer = service("authorization")
authentication = service("authentication")

@script("create-group", "-g")
def group(name=None, description=None):
	while not bool(name):
		name = name or input("Enter group name: ")
	authorizer.create_group(name, description or input("Enter group description: "))

@script("create-user", "-u")
def user(username=None, password=None, passconfirm=None, email=None, group="user"):
	while not bool(username):
		username = username or input("Enter username: ")
	
	while (password is None and passconfirm is None) and (password != passconfirm):
		while not bool(password):
			password = password or input("Enter password: ")
		while not bool(passconfirm):
			passconfirm = passconfirm or input("Enter password (again): ")
		if password != passconfirm:
			print("Password don't match.")
	
	email = email or input("Enter email: ")
	group = group or input("Enter group: ")

	code = authentication.register(username, password, email, group)
	authentication.validate_registration(code)

@script("create-demo")
def setup_demo():
	group("admin", "Admin User Group")
	group("user", "Regular User Group")
	user("admin", "admin", "admin", "gamerxville@gmail.com", "admin")
	user("user", "user", "user", "gamerxville2k20@gmail.com", "user")
	# GroupsUsers.Meta.database.execute(
	# 	"INSERT INTO auth_group_users (group, user) VALUES (1, 1)"
	# )
	# GroupsUsers.Meta.database.execute(
	# 	"INSERT INTO auth_group_users (group, user) VALUES (2, 2)"
	# )
	authorizer.add_user_to_group(1, 1)
	authorizer.add_user_to_group(2, 2)
	