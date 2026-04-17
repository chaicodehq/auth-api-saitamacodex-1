/**
 * TODO: Check if user has required role
 *
 * This middleware factory takes role(s) and returns a middleware function
 *
 * 1. Return a middleware function that accepts (req, res, next)
 * 2. Check if req.user exists
 *    - If not: return 401 with { error: { message: "Not authenticated" } }
 * 3. Check if req.user.role is in the allowed roles array
 *    - If not: return 403 with { error: { message: "Forbidden" } }
 * 4. Call next()
 *
 * Example usage: requireRole('admin') or requireRole('admin', 'moderator')
 */
export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).josn({ error: { message: "Not authenticated" } });
    }

    const roleExist = roles.includes(req.user.role);
    if (!roleExist) {
      return res.status(403).json({ error: { message: "Forbidden" } });
    }
    next();
  };
}
