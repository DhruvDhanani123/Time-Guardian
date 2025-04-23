const mongoose = require('mongoose');

const LeaveEmployeeSchema = new mongoose.Schema({
    emp_name: String,
    email : String
});

const LeaveEmployeeModel = mongoose.model('LeaveRequest', LeaveEmployeeSchema);
module.exports = LeaveEmployeeModel;
