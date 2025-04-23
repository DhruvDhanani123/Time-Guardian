const mongoose =require('mongoose');

const EmployeeInfoSchema = new mongoose.Schema({
    fName : {
        type : String,
        required : true
    },
    email: {
        type : String,
        required : true
    },    
    mono : {
        type : String,
        required : true
    },
    joinDate : {
        type : String,
        required : true
    },
    salary: {
        type : String,
        required : true
    }
});

const EmployeeInfoModel = mongoose.model('EmployeeInfo',EmployeeInfoSchema);
module.exports=EmployeeInfoModel;