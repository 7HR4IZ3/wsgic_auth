# import json
# from wsgic.backend.bottle import static_file
# from wsgic.backend.cork import Cork
# from wsgic.http import request, response, redirect
# from wsgic.backend.cork.sqlite_backend import SQLiteBackend
# from wsgic.views import View, render
# from wsgic.helpers import messages, hooks, url_to, config
# from wsgic.session import sessions

# from .helpers import auth, jwtauth
# from .models import User

# users = User()

# if not auth.user('admin'):
#     auth.setup_demo()

# class AuthView(View):
#     def login(self):
#         """Authenticate users"""
#         if auth.user_is_anonymous:
#             if request.method == "GET":
#                 messages.add("Login or create an account")
#                 return render("auth-login.html")
#             else:
#                 username = request.POST.username
#                 password = request.POST.password
#                 auth.login(username, password, success_redirect=config.get("login_redirect") or request.previous_url, fail_redirect=url_to('auth_login'))
#                 messages.add("Logged in successfully")
#         else:
#             # redirect(url_to("login")))
#             redirect().to(config.get("login_redirect") or "/")
#             return render("index.html")

#     def generate(self):
#         if auth.logged_in():
#             return str(jwtauth.generate(auth.current_user))
#         else:
#             redirect().to("auth_login").message('Login to generate auth token')

#     def logout(self):
#         auth.logout(success_redirect=url_to(config.get("logout_redirect")) or request.previous_url)

#     def register(self):
#         """Send out registration email"""
#         auth.register(request.POST.get('username'), request.POST.get('password'), request.POST.get('email_address'))
#         return 'Please check your mailbox.'

#     def validate(self, code):
#         """Validate registration, create user account"""
#         auth.validate_registration(code)
#         return 'Thanks. <a href="%s">Go to login</a>' %url_to('auth_login')

#     def send_password_reset_email(self):
#         """Send out password reset email"""
#         auth.send_password_reset_email(
#             username=request.POST.get('username'),
#             email_addr=request.POST.get('email_address')
#         )
#         return 'Please check your mailbox.'

#     def change_password_validate(self, code):
#         """Show password change form"""
#         return dict(reset_code=code)

#     def change_password(self):
#         """Change password"""
#         auth.reset_password(request.POST.get('reset_code'), request.POST.get('password'))
#         return 'Thanks. <a href="%s">Go to login</a>' %url_to('auth_login')

#     def status(self):
#         return f"Logged in as {request.user.username}" if request.user else f"Not logged in"
    
#     def details(self):
#         if request.user:
#             user = (users.username==request.user.username)[0]
#             user.pop('hash')
#             return json.dumps(user)
#         else:
#             return 'Login first'


# # class MainView(View):
# #     # @auth.require(fail_redirect=url_to('auth_login'))))
# #     def index(self):
# #         """Only authenticated users can see this"""
# #         auth.login_required(fail_redirect=url_to('auth_login')))

# #         return 'Welcome! <a href="%s">Admin page</a> <form method="POST" action="%s"><input type="submit" value="Logout"></form>' %('/admin'), url_to('auth_logout')))

# #     def user_is_anonymous(self):
# #         return f"Logged in as {auth.current_user.username}" if not auth.user_is_anonymous else f"Not logged in."

# #     def sorry_page(self, e):
# #         """Serve sorry page"""
# #         return '<p>Sorry, you are not authorized to perform this action</p>' + "\n" + f""""
# # <h1>Traceback</h1>
# # <p>{e}</p>
# # """
    
# #     def restricted_download(self):
# #         """Only authenticated users can download this file"""
# #         auth.login_required(fail_redirect=url_to('auth_login')))

# #         return static_file('static_file', root='.')

# #     def current_user_role(self):
# #         """Show current user role"""
# #         auth.login_required(fail_redirect=url_to('auth_login')))

# #         return auth.current_user.role
    
# #     def me(self):
# #         return f"{auth.current_user.info}"

# # class AdminView(View):
# #     def index(self):
# #         """Only admin users can see this"""
# #         auth.login_required(role='admin', fail_redirect=url_to('auth_login')))
# #         return render('admin_page.html', dict(
# #             current_user=auth.current_user,
# #             users=auth.list_users(),
# #             roles=auth.list_roles(),
# #             url=#/         ))

# #     def create_user(self):
# #         try:
# #             auth.create_user(request.forms.username, request.forms.role, request.forms.password)
# #             return dict(ok=True, msg='')
# #         except Exception as e:
# #             return dict(ok=False, msg="An error occured")


# #     def delete_user(self):
# #         try:
# #             auth.delete_user(request.POST.get('username'))
# #             return dict(ok=True, msg='')
# #         except Exception as e:
# #             print(repr(e))
# #             return dict(ok=False, msg="An error occured")


# #     def create_role(self):
# #         try:
# #             auth.create_role(request.POST.get('role'), request.POST.get('level'))
# #             return dict(ok=True, msg='')
# #         except Exception as e:
# #             return dict(ok=False, msg="An error occured")


# #     def delete_role(self):
# #         try:
# #             auth.delete_role(request.POST.get('role'))
# #             return dict(ok=True, msg='')
# #         except Exception as e:
# #             return dict(ok=False, msg="An error occured")

# # # def setup_demo():
# # #     # db.Role.new(role='admin', level= 100)
# # #     # db.Role.new(role='editor', level= 60)
# # #     # db.Role.new(role='user', level= 50)
# # #     tstamp = str(datetime.utcnow())
    
# # #     username = password = 'admin'
# # #     db.User.new({
# # #         'username': username,
# # #         'role': 'admin',
# # #         'hash': str(auth._hash(username, password)).encode("ascii"),
# # #         'email_addr': username + '@localhost.local',
# # #         'desc': username + ' test user',
# # #         'creation_date': tstamp,
# # #         "last_login": tstamp
# # #     })

# # #     username = password = 'demo'
# # #     db.User.new({
# # #         'username': username,
# # #         'role': 'user',
# # #         'hash': str(auth._hash(username, password)).encode("ascii"),
# # #         'email_addr': username + '@localhost.local',
# # #         'desc': username + ' test user',
# # #         'creation_date': tstamp, 
# # #         "last_login": tstamp
# # #     })
# # #     db.commit()
# # # auth.setup_demo()
# # # print(db)

# # # auth.register_user("admin", "admin", "admin")