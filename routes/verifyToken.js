const jwt = require('jsonwebtoken')


const verifyToken = (req,res,next)=>{
    const authHeader = req.headers.token
    if(authHeader){
        const token = authHeader.split(" ")[1];
        jwt.verify(token, process.env.JWT_SEC, (err, user) => {
            if(err) res.status(403).json("Token is not valid!");
            req.user = user;
            next();
        })
    }else{
        return res.status(401).json("You are not authenticated!")
    }
}

const verifyTokenAndAuthorization = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.id === req.params.id || req.user.idAdmin) {
            next();
        } else {
            res.status(403).json("You are not alowed to do that!");
        }
    })
}

const verifyTokenAndAdmmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.idAdmin == true) {
            next();
        } else {
            res.status(403).json("Admin are just alowed to do that!");
        }
    })
}

module.exports = 
    {   
        verifyToken, 
        verifyTokenAndAuthorization, 
        verifyTokenAndAdmmin 
    }
