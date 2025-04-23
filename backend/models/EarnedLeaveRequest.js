const mongoose = require('mongoose');

const EarnedLeaveEmployeeSchema = new mongoose.Schema({
    emp_name: String,
    email : String, 
    status:String
});

const EarnedLeaveEmployeeModel = mongoose.model('EarnedLeaveRequests', EarnedLeaveEmployeeSchema);
module.exports = EarnedLeaveEmployeeModel;
