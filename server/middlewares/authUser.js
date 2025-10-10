// import jwt from 'jsonwebtoken';

// const authUser = async (req, res, next)=>{
//     const {token} = req.cookies;

//     if(!token){
//         return res.json({success:false, message: 'Not authorized 1'});
//     }

//     try {
//         const tokenDecode = jwt.verify(token, process.env.JWT_SECRET)
//         if(tokenDecode.id){
//             req.body.userId = tokenDecode.id;
//         }else{
//             return res.json({success:false, message: 'Not authorized 2'});
//         }
//         next();
//     } catch (error) {
//         return res.json(
//             {
//                 success:false, 
//                 message: "Not Authorized 3",
//                 "errorMessage": error.message
//             }
//         );
//     }
// }


// export default authUser;

import jwt from 'jsonwebtoken';

const authUser = async (req, res, next) => {
  try {
    const { token } = req.cookies || {};

    if (!token) {
      return res.status(401).json({ success: false, message: 'Not authorized: No token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded?.id) {
      return res.status(401).json({ success: false, message: 'Not authorized: Invalid token' });
    }

    // ✅ FIXED: attach userId to req (not req.body)
    req.userId = decoded.id;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Not authorized: Token verification failed',
      errorMessage: error.message,
    });
  }
};

export default authUser;
