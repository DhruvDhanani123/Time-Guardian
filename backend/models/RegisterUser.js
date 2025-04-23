const mongoose =require('mongoose');
const RegisterUsersSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    mono: {
        type: String,
        required: true
    },
    is_admin:{
        type:Number,
        required : true
    }
});

const RegisterUserModel = mongoose.model('RegisterUser',RegisterUsersSchema);
module.exports= RegisterUserModel;