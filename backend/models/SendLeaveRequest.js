const mongoose = require('mongoose');

const SendLeaveEmployeeSchema = new mongoose.Schema({
    emp_name: String,
    email : String
});

const SendLeaveEmployeeModel = mongoose.model('PersonalInfos', SendLeaveEmployeeSchema);
module.exports = SendLeaveEmployeeModel;
