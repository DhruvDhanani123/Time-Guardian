const mongoose =require('mongoose');

const PersonalInfoSchema = new mongoose.Schema({
    username: {
        type : String,
        required : true
    },
    fName : {
        type : String,
        required : true
    },
    bDate :{
        type : String,
        required : true
    },
    mono : {
        type : String,
        required : true
    },
    address : {
        type : String,
        required : true
    }, 
    city : {
        type : String,
        required : true
    }, 
    state : {
        type : String,
        required : true
    },
});

const PersonalInfoModel = mongoose.model('PersonalInfo',PersonalInfoSchema);
module.exports=PersonalInfoModel;