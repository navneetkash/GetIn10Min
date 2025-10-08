import user from "../models/user.js";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';


// Register user : /api/user/register
export const register = async (req, res)=>{
    try {
        const {name, email, password} = req.body;
        if(!name || !email || !password){
            return res.json({success: false, message: "Missing Details"})
        }

        const existingUser = await user.findOne({email})

        if(existingUser){
            return res.json({success: false, message: "User already exist"})
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const User = await user.create({name, email, password: hashedPassword})

        const token = jwt.sign({id:User._id}, process.env.JWT_SECRET, {expiresIn:'7d'})

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', //Use secure cookie in production
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', // CSRF protection
            maxAge: 7 * 24 * 60 * 60 * 1000
        })
        return res.json({success: true, User: {email: User.email, name: User.name}})
    } catch (error) {
        console.log(error.message);
        res.json({success: false, message: error.message});
    }
}

// Login user /api/user/login

export const login = async (req, res)=>{
    try {
        const {email, password} = req.body;

        if(!email || !password){
            return res.json({success: false, message: 'Email and password are required'});
        }

        const User = await user.findOne({email});

        if(!User){
            return res.json({success: false, message: 'Invalid Email or password'});
        }

        const isMatch = await bcrypt.compare(password, User.password)

        if(!isMatch){
            return res.json({success: false, message: 'Invalid Email or password'});
        }

        const token = jwt.sign({id:User._id}, process.env.JWT_SECRET, {expiresIn:'7d'})

        res.cookie('token', token, {
            httpOnly: true,  // Prevent javascript to access cookies
            secure: process.env.NODE_ENV === 'production', //Use secure cookie in production
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', // CSRF protection
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        return res.json({success: true, User: {email: User.email, name: User.name}})
    } catch (error) {
        console.log(error.message);
        res.json({success: false, message: error.message});
    }
}


// Check Auth : /api/user/is-auth

export const isAuth = async (req, res)=>{
    try {
        const {userId} = req.body;
        const User = await user.findById(userId).select("=password");
        return res.json({success: true, user})
    } catch (error) {
        console.log(error.message);
        res.json({success: false, message: error.message});
    }
}

// Logout user : /api/user/logout

export const logout = async (req, res)=>{
    try {
        res.clearCookie('token', {
            httpOnly: true,  // Prevent javascript to access cookies
            secure: process.env.NODE_ENV === 'production', //Use secure cookie in production
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', // CSRF protection
        });
        return res.json({success: true, message: "Logged Out"})
    } catch (error) {
        console.log(error.message);
        res.json({success: false, message: error.message});
    }
}