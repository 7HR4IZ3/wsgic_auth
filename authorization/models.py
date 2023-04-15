from ..models import *
from wsgic.services import register, service
from wsgic.services.cache import SimpleCache

cache: SimpleCache = service("cache.simple")

is_array = lambda x: isinstance(x, list)
is_numeric = lambda x: isinstance(x, int)
is_string = lambda x: isinstance(x, str)
in_array = lambda key, arr, e: key in arr
array_column = lambda arr, key: [getattr(x, key) for x in arr] 
lang = lambda *x: "Lang..."
strtolower = lambda x: x.lower()

def array_merge(*a):
    ret =[]
    for x in a:
        for y in x:
            ret.append(y)
    return ret

class PermissionModel:
    model = Permissions
    table         = 'auth_permissions'
    allowedFields = [
        'name', 'description',
    ]
    useTimestamps   = False
    validationRules = {
        'name'        : 'required|max_length[255]|is_unique[auth_permissions.name,name:name]',
        'description' : 'max_length[255]',
    }

    """
     * Checks to see if a user, or one of their groups,
     * has a specific permission.
    """
    def does_user_have_permission(self, userId, permissionId):
        # Check user permissions and take advantage of caching
        userPerms = self.get_permissions_for_user(userId)

        if (len(userPerms) > 0 and permissionId in userPerms):
            return True
        

        # Check group permissions
        # count = GroupsPermissions.join('auth_groups_users', 'auth_groups_users.group_id = auth_groups_permissions.group_id', 'inner').where('auth_groups_permissions.permission_id', permissionId).where('auth_groups_users.user_id', userId).countAllResults()
        count = len(
            GroupsPermissions.Meta.objects.get(user=userId)
        )

        return count > 0
    

    """
     * Adds a single permission to a single user.
     *
     * @return BaseResult|False|Query
    """
    def add_permission_to_user(self, permissionId, userId):
        cache.delete(f"{userId}_permissions")

        return UsersPermissions.Meta.objects.create(**{
            'user'       : userId,
            'permission' : permissionId,
        })
    

    """
     * Removes a permission from a user.
     *
     * @return mixed
    """
    def remove_permission_from_user(self, permissionId, userId):
        UsersPermissions.Meta.objects.delete(**{
            'user'       : userId,
            'permission' : permissionId,
        })

        cache.delete(f"{userId}_permissions")
    

    """
     * Gets all permissions for a user in a way that can be
     * easily used to check against:
     *
     * [
     *  id : name,
     *  id : name
     * ]
    """
    def get_permissions_for_user(self, userId):
        found = cache.get(f"{userId}_permissions")
        if (None == found):
            # fromUser = UsersPermissions.select().join('auth_permissions', 'auth_permissions.id = permission', 'inner').where('user_id', userId).get().getResultObject()
            fromUser = UsersPermissions.Meta.objects.get('id', 'name', user=userId)

            # fromGroup = GroupsUsers.select('auth_permissions.id, auth_permissions.name').join('auth_groups_permissions', 'auth_groups_permissions.group_id = auth_groups_users.group_id', 'inner').join('auth_permissions', 'auth_permissions.id = auth_groups_permissions.permission_id', 'inner').where('user_id', userId).get().getResultObject()
            fromGroup = GroupsUsers.Meta.objects.get("id", "name", user=userId)

            combined = array_merge(fromUser, fromGroup)

            found = []

            for row in combined:
                found[row.id] = strtolower(row.name)
            

            cache.set(f"{userId}_permissions", found, 300)

        return found

class GroupModel:
    model = Groups
    returnType = 'object'
    allowedFields = [
        'name', 'description',
    ]
    useTimestamps   = False
    validationRules = {
        'name' : 'required|max_length(255)|is_unique[auth_groups.name,name,{name}]',
        'description' : 'max_length(255)',
    }
    validationMessages = []
    skipValidation     = False

    #--------------------------------------------------------------------
    # Users
    #--------------------------------------------------------------------

    """
     * Adds a single user to a single group.
     *
     * @return bool
    """
    def add_user_to_group(self, userId: int, groupId: int):
        cache.delete(f"{groupId}_users")
        cache.delete(f"{userId}_groups")
        cache.delete(f"{userId}_permissions")

        data = {
            'user'  : userId,
            'group' : groupId,
        }
        GroupsUsers.Meta.objects.create(**data)
        return GroupsUsers.Meta.objects.get(**data)


    """
     * Removes a single user from a single group.
     *
     * @param int|string groupId
     *
     * @return bool
    """
    def remove_user_from_group(self, userId: int, groupId):
        cache.delete(f"{groupId}_users")
        cache.delete(f"{userId}_groups")
        cache.delete(f"{userId}_permissions")

        return GroupsUsers.Meta.objects.delete(**{
                'user'  : userId,
                'group' : int(groupId),
        })


    """
     * Removes a single user from all groups.
     *
     * @return bool
    """
    def remove_user_from_all_groups(self, userId: int):
        cache.delete(f"{userId}_groups")
        cache.delete(f"{userId}_permissions")

        return GroupsUsers.Meta.objects.delete(user=userId)


    """
     * Returns an array of all groups that a user is a member of.
     *
     * @return array
    """
    def get_groups_for_user(self, userId: int):
        found = cache.get(f"{userId}_groups")
        if not found:
            # found = self.builder().select('auth_groups_users.*, auth_groups.name, auth_groups.description').join('auth_groups_users', 'auth_groups_users.group_id = auth_groups.id', 'left').where('user_id', userId).get().getResultArray()
            
            found = GroupsUsers.Meta.objects.get(user=userId)

            cache.set(f"{userId}_groups", found, 300)

        return found


    """
     * Returns an array of all users that are members of a group.
     *
     * @return array
    """
    def get_users_for_group(self, groupId: int):
        found = cache.get(f"{groupId}_users")
        if not found:
            # found = self.builder().select('auth_groups_users.*, users.*').join('auth_groups_users', 'auth_groups_users.group_id = auth_groups.id', 'left').join('users', 'auth_groups_users.user_id = users.id', 'left').where('auth_groups.id', groupId).get().getResultArray()

            found = GroupsUsers.Meta.objects.get(group=groupId)

            cache.set(f"{groupId}_users", found, 300)

        return found


    #--------------------------------------------------------------------
    # Permissions
    #--------------------------------------------------------------------

    """
     * Gets all permissions for a group in a way that can be
     * easily used to check against:
     *
     * [
     *  id : name,
     *  id : name
     * ]
    """
    def get_permissions_for_group(self, groupId: int):
        # fromGroup       =Permissions.select('auth_permissions.*').join('auth_groups_permissions', 'auth_groups_permissions.permission_id = auth_permissions.id', 'inner').where('group_id', groupId).findAll()

        fromGroup = Permissions.Meta.objects.get(group=groupId)

        found = []

        for permission in fromGroup:
            found[permission['id']] = permission

        return found


    """
     * Add a single permission to a single group, by IDs.
     *
     * @return mixed
    """
    def add_permission_to_group(self, permissionId: int, groupId: int):
        data = {
            'permission' : permissionId,
            'group'      : groupId,
        }

        return GroupsPermissions.Meta.objects.create(**data)


    #--------------------------------------------------------------------

    """
     * Removes a single permission from a single group.
     *
     * @return mixed
    """
    def remove_permission_from_group(self, permissionId: int, groupId: int):
        return GroupsPermissions.Meta.objects.delete(**{
                'permission' : permissionId,
                'group'      : groupId
            })


    #--------------------------------------------------------------------

    """
     * Removes a single permission from all groups.
     *
     * @return mixed
    """
    def remove_permission_from_all_groups(self, permissionId: int):
        return GroupsPermissions.Meta.objects.delete(permission=permissionId)
