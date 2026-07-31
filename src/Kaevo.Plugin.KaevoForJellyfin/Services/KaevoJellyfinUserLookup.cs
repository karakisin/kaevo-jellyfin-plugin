using System.Collections;
using System.Reflection;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// <summary>
/// Resolves Jellyfin users without binding the plugin assembly to the return
/// type of IUserManager.GetUserById. Jellyfin 10.11 moved the User type, so a
/// plugin compiled against 10.10 can otherwise fail with MissingMethodException
/// before its own error handling runs.
/// </summary>
internal static class KaevoJellyfinUserLookup
{
    internal static bool Exists(object? userManager, Guid expectedId)
    {
        if (userManager is null || expectedId == Guid.Empty)
        {
            return false;
        }

        try
        {
            var managerType = userManager.GetType();
            var ids = managerType.GetMethod(
                    "GetUsersIds",
                    BindingFlags.Instance | BindingFlags.Public,
                    binder: null,
                    types: Type.EmptyTypes,
                    modifiers: null)?.Invoke(userManager, null)
                ?? managerType.GetProperty(
                    "UsersIds",
                    BindingFlags.Instance | BindingFlags.Public)?.GetValue(userManager);
            if (ids is not IEnumerable userIds)
            {
                return false;
            }

            foreach (var value in userIds)
            {
                if (TryReadId(value, out var actualId) && actualId == expectedId)
                {
                    return true;
                }
            }

            return false;
        }
        catch (Exception)
        {
            // A runtime contract mismatch must fail closed instead of allowing
            // a Cloud profile to bind to an unverified Jellyfin identity.
            return false;
        }
    }

    private static bool TryReadId(object? value, out Guid id)
    {
        id = Guid.Empty;
        if (value is Guid guid)
        {
            id = guid;
            return guid != Guid.Empty;
        }

        return value is string text
            && Guid.TryParse(text, out id)
            && id != Guid.Empty;
    }
}
