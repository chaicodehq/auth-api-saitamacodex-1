import bcrypt from "bcryptjs";
import { User } from "../models/user.model.js";
import { signToken } from "../utils/jwt.js";

/**
 * TODO: Register a new user
 *
 * 1. Extract name, email, password from req.body
 * 2. Check if user with email already exists
 *    - If yes: return 409 with { error: { message: "Email already exists" } }
 * 3. Create new user (password will be hashed by pre-save hook)
 * 4. Return 201 with { user } (password excluded by default)
 */
export async function register(req, res, next) {
  try {
    // Your code here
    const { name, email, password, role } = req.body;
    const isUserExist = await User.findOne({ email });

    if (isUserExist) {
      const error = new Error("Email already exists");
      error.statusCode = 409;
      return next(error);
    }
    // user creation
    // any validation error occurs during insert, it will throw an error
    // and we will pass it to mext middleware
    const user = await User.create({
      name,
      email,
      password,
      role,
    });

    const userObj = user.toObject();
    delete userObj.password;

    return res.status(201).json({
      user: userObj,
    });
  } catch (error) {
    // here "error" is an object
    next(error);
  }
}

/**
 * TODO: Login user
 *
 * 1. Extract email, password from req.body
 * 2. Find user by email (use .select('+password') to include password field)
 * 3. If no user found: return 401 with { error: { message: "Invalid credentials" } }
 * 4. Compare password using bcrypt.compare(password, user.password)
 * 5. If password wrong: return 401 with { error: { message: "Invalid credentials" } }
 * 6. Generate JWT token with payload: { userId: user._id, email: user.email, role: user.role }
 * 7. Return 200 with { token, user } (exclude password from user object)
 */
export async function login(req, res, next) {
  try {
    const { email, password: clearTextPass } = req.body;
    const findUser = await User.findOne({ email }).select("+password");
    if (!findUser) {
      return res
        .status(401)
        .json({ error: { message: "Invalid credentials" } });
    }
    const isPassMatched = await bcrypt.compare(
      clearTextPass,
      findUser.password,
    );
    if (!isPassMatched) {
      return res.status(401).json({
        error: {
          message: "Invalid credentials",
        },
      });
    }

    // generate tokens
    const token = signToken({
      userId: findUser._id,
      email: findUser.email,
      role: findUser.role,
    });

    const userObj = findUser.toObject();
    delete userObj.password;

    res.status(200).json({
      user: userObj,
      token: token,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * TODO: Get current user
 *
 * 1. req.user is already set by auth middleware
 * 2. Return 200 with { user: req.user }
 */
export async function me(req, res, next) {
  try {
    return res.status(200).json({
      user: req.user,
    });
  } catch (error) {
    next(error);
  }
}
