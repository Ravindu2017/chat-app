import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
  try {
    // are there any cookies
    const token = req.cookies.jwt;

    // No cookie
    if (!token) {
      return res
        .status(401)
        .json({ message: "Unauthorized - No Token Provided" });
    }

    // Type of cookie
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Incorrect type of cookie
    if (!decoded) {
      return res.status(401).json({ message: "Unauthorized - Invalid Token" });
    }

    // Find user but do not return password
    const user = await User.findById(decoded.userId).select("-password");

    // Found no such user
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // assign request user body as matching user we found
    req.user = user;

    next();
  } catch (error) {
    console.log("Error in protectRoute in middleware", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
