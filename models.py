# from wsgic.database.sqlite import SqliteDatabase, Column
from wsgic.database import database
from wsgic.database.columns import *
from wsgic.helpers import config
from wsgic.handlers.files import FileSystemStorage

# db = SqliteDatabase(config.get("databases.sqlite.path", "database.sqlite"), config.get("databases.sqlite.debug", False), verbose=config.get("databases.sqlite.verbose", False), check_same_thread=False)

@database.on('error')
def error(e):
    raise e

# store = FileSystemStorage(directory="./media").create()
# uploads = store["uploads"].create()

class Role(database.Model):
    role: str = SelectColumn(options=["admin", "editor", "user", "superuser"])
    level: int = IntegerColumn(null=False, min=1, max=100)

    def __str__(self):
        return f"[{self.id}] role -> {self.role}: level -> {self.level}"

    class Meta:
        table_name = "auth_role"

class User(database.Model):
    username: str
    email_addr: str = EmailColumn(label="Email Address", helper_text="User's email address: '@' must be present", unique=True)
    desc: str = RichTextColumn(label="Description", helper_text="Description of the user")
    creation_date: datetime = DateTimeColumn(null=False)
    # image: str = ImageColumn(extensions=["jpg", "png"], store=uploads, default="default.png", label="Image")
    last_login: datetime = DateTimeColumn()
    hash: bytes = BytesColumn(null=False)

    @property
    def tag(self):
        return f"@{self.username}".lower()
    
    def __str__(self):
        return f"[{self.id}] username -> {self.username}"
    
    class Meta:
        table_name = "auth_users"

# bob = User(name="bob")
# role = bob.role
# role.user

# class Notification(database.Model):
#     __table_name = "wsgic_notification"

class PendingReg(database.Model):
    code: str
    email_addr: str = EmailColumn(label="Email Address")
    desc: str = QuillEditorColumn(editor="full", label="Description")
    hash: bytes = BytesColumn(null=False)
    username: str = Column(null=False)
    creation_date: datetime = DateTimeColumn(null=False, label="Date Created")
    
    class Meta:
        table_name = "auth_pending_registrations"

class Token(database.Model):
    tokenid: str
    last_used: datetime = DateTimeColumn(null=True)
    is_expired = BooleanColumn(default=False)
    usage_amount: int = IntegerColumn(default=0)
    usage_limit: int = IntegerColumn()
    user = ForeignKeyColumn(User)
    value: str = Column(null=False)
    creation_date: datetime = DateTimeColumn(null=False, label="Created")
    expiry_date: datetime = DateTimeColumn(null=True)
    
    @property
    def owner(self):
        return User.objects.get(id=self.user_id)
    
    class Meta:
        table_name = "auth_tokens"

class AuthAttempts(database.Model):
    ip_address: str = Column(null=False)
    user_agent: str = Column(null=False)
    token: str = Column(null=False)
    created_at = DateTimeColumn()

    class Meta:
        table_name = "auth_activation_attempts"

class Permissions(database.Model):
    name: str = Column(null=False)
    description: str = Column(null=False)

    class Meta:
        table_name = 'auth_permissions'

class UsersPermissions(database.Model):
    user = ForeignKeyColumn(User)
    permission = ForeignKeyColumn(Permissions)

    class Meta:
        table_name = 'auth_users_permissions'

    # @property
    # def user(self):
    #     return User.Meta.objects.get(id=self.user)

    # @property
    # def permission(self):
    #     return Permissions.Meta.objects.get(id=self.permission)

class Groups(database.Model):
    name: str = Column(null=False)
    description: str = Column(null=False)

    class Meta:
        table_name = 'auth_groups'

class GroupsUsers(database.Model):
    user: int = ForeignKeyColumn(User)
    group: int = ForeignKeyColumn(Groups, name="user_group")

    class Meta:
        table_name = 'auth_groups_users'
    
    # @property
    # def group(self):
    #     return Groups.Meta.objects.get(id=self.group)
    
    # @property
    # def user(self):
    #     return User.Meta.objects.get(id=self.user)

class GroupsPermissions(database.Model):
    group = ForeignKeyColumn(Groups, name="user_group")
    permission = ForeignKeyColumn(Permissions)

    class Meta:
        table_name = 'auth_groups_permissions'

    # @property
    # def group(self):
    #     return Groups.Meta.objects.get(id=self.group)
    
    # @property
    # def permission(self):
    #     return Permissions.Meta.objects.get(id=self.permission)

####
    # STATUS = (
    #     (0, "Draft"),
    #     (1, "Published")
    # )


    # class Category(Model): #Category for the Article
    #     title: str = Column(max_length=200) #Title of the Category
    #     created_on: datetime = DateTimeColumn(auto_now_add=True) #Date of creation

    #     def __str__(self):
    #         return self.title


    # class BlogPost(Model):
    #     title: str = Column(max_length=200, unique=True) #Title of the Article
    #     slug: str = Column(max_length=200, unique=True) #Unique identifier for the article
    #     author = ForeignKeyColumn(User, related_name='blog_posts') #Author of the Article
    #     description: str = Column(max_length=500) #Short Description of the article
    #     content: str = RichTextColumn(config_name='awesome_ckeditor') #Content of the article, you need to install CKEditor
    #     tags: str # = TaggableManager() #Tags for a Particular Article, You need to install Taggit
    #     category = ForeignKeyColumn('Category', related_name='category') #Category of the article
    #     keywords: str = Column(max_length=250) #Keywords to be used in SEO
    #     cover = ImageColumn(upload_to='images/') #Cover Image of the article
    #     created_on: datetime = DateTimeColumn(auto_now_add=True) #Date of creation
    #     updated_on: datetime = DateTimeColumn(auto_now=True) #Date of updation
    #     status: int = IntegerColumn(choices=STATUS, default=0) #Status of the Article either Draft or Published

    #     def __str__(self):
    #         return self.title

    #     def get_absolute_url(self):
    #         return reverse("blog:detail", args=[str(self.slug)])

    # Role = db.table("Role", {
    #     'role': db.column("text"),
    #     'level': db.column("integer", null=False)
    # })

    # User = db.table("User", {
    #     'username': db.column("text"),
    #     'role': db.column("text"),
    #     'hash': db.column("bytes", null=False),
    #     'email_addr': db.column("text"),
    #     'desc': db.column("text"),
    #     'creation_date': db.column("text", null=False),
    #     'last_login': db.column("text", null=True)
    # })


    # PendingReg = db.table("PendingReg", {
    #     'code': db.column("text"),
    #     'username': db.column("text", null=False),
    #     'role': db.column("text"),
    #     'hash': db.column("bytes", null=False),
    #     'email_addr': db.column("text"),
    #     'desc': db.column("text"),
    #     'creation_date': db.column("text", null=False)
    # })
