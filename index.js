const express = require('express');
const app = express();
const mongodb = require('mongodb');
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoClient = mongodb.MongoClient;
const dbUrl = process.env.DB_URL || 'mongodb://127.0.0.1:27017';
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());

//below api is used for user registration
app.post('/register',async(req,res)=>{
    try{
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        let check = await db.collection('users').findOne({email:req.body.email});
        if(check){
          res.send(400).json({message:"User already present"});
        }
        else{
          let salt =await bcrypt.genSalt(10);
          let hash = await bcrypt.hash(req.body.password, salt);
          req.body.password = hash;
          let postData = {
              email:req.body.email,
              isActiveSession:false,
              stats:{
              totalSessions:0,    
              streak:0,
              avg:0,
              longestFast:0,
              longestStreak:0,
              },
              sessions:[]
          }
          let resp = await db.collection('users').insertOne(req.body);
          await db.collection('userSessions').insertOne(postData);      
          res.status(200).json({message:"Session & user created"});
          clientInfo.close();
        } 
        
    }
    catch(e){
        console.log(e);
    }
})

//below api is used for user login
app.post('/login',async(req,res)=>{

        try{
            let clientInfo = await mongoClient.connect(dbUrl);
            let db = clientInfo.db('app');
            let check = await db.collection('users').findOne({email:req.body.email});
            if(check){
                let checkPassword = await bcrypt.compare(req.body.password, check.password); 
                if(checkPassword){
                   let token = await jwt.sign(
                       {user_id: check._id},
                       process.env.JWT_KEY
                   )

                   res.status(200).json({message:"User logged In.",token:token})
                }
                else{
                    res.send(400).json({message:"Incorrect password."});    
                }
            }
            else{
                    res.send(404).json({message:"User not present"});
            }
            clientInfo.close();
           }
           catch(e){
              console.log(e);  
           }  

})

//below api is used for sending user data.
app.get("/showdata",authenticate,async(req,res)=>{
    try{
       let clientInfo = await mongoClient.connect(dbUrl);
       let db = clientInfo.db('app');
       let sessionData = await db.collection('userSessions').findOne({email:req.query.email});
       res.status(200).json({message:"Success",data:sessionData}); 
       clientInfo.close();
    } 
    catch(e){
       console.log(e);
    }
})

//below api is used for saving newly created session.
app.post("/createSession",authenticate,async(req, res)=>{
    try{
    let clientInfo = await mongoClient.connect(dbUrl);
    let db = clientInfo.db('app');
    let userSessionData = await db.collection('userSessions').findOne({email:req.body.email});
    let sessionsData = userSessionData.sessions;
    sessionsData.push(req.body.session);
    await db.collection('userSessions').findOneAndUpdate({email:req.body.email},{$set:{sessions:sessionsData,isActiveSession:true}});  
    res.status(200).json({message:"Session created"})
    clientInfo.close(); 
    }
    catch(e){
        console.log(e);
    }
})

//below api is used for editing the session info.
app.post('/changeValues',authenticate,async(req,res) => {
      try{     
        let clientInfo = await mongoClient.connect(dbUrl);
        let db = clientInfo.db('app');
        let userSessionData = await db.collection('userSessions').findOne({email:req.body.email});
        let sessionsData = userSessionData.sessions;
        let num =sessionsData.length
        let sess = sessionsData;
        sess[num-1] = req.body.updatedSession;
        await db.collection('userSessions').findOneAndUpdate({email:req.body.email},{$set:{sessions:sess}});  
        res.status(200).json({message:"Success"});
        clientInfo.close();  
      }                      
      catch(e){
          console.log(e);
      }
})

//below api is used for saving details of finished session.
app.post('/sessionComplete',authenticate,async(req,res) => {
    try{
      let clientInfo = await mongoClient.connect(dbUrl);
      let db = clientInfo.db('app');
      let userSessionData = await db.collection('userSessions').findOne({email:req.body.email});
      let sessionsData = userSessionData.sessions;
      let num =sessionsData.length
      let sess = sessionsData;
        
        sess[num-1] = req.body.finalSession;
      await db.collection('userSessions').findOneAndUpdate({email:req.body.email},{$set:{sessions:sess,isActiveSession:false,stats:req.body.stats}});  
      res.status(200).json({message:"Success"});
      clientInfo.close();  
    }                      
    catch(e){
        console.log(e);
    }
})



//for token authentication.
function authenticate(req,res,next){
    if(req.headers.authorisation !== undefined){
        jwt.verify(
           req.headers.authorisation,
           process.env.JWT_KEY,
           (err,decode)=>{
              if(decode !== undefined){
                  next();
              }
              else{
               res.send(401).json({message:"No authorisation."})          
              }
           }             
        ) 
    } 
    else{
        res.send(401).json({message:"No authorisation."})
    }
}


app.listen(port, ()=>{console.log("Server is listening on port"+ port);})