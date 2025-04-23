const mongoose = require('mongoose');

const AttendanceSchema = new mongoose.Schema({
    username: {
        type : String,
        required : true
    },
    // start_time: Date,
    // end_time: Date,
    day : {
        type : String,
        required : true
    },
    duration: {
        type : Number,
        required : true
    },
});

const AttendanceModel = mongoose.model('Attendance', AttendanceSchema);
module.exports = AttendanceModel;
