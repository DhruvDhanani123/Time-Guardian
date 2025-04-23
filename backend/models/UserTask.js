const mongoose =require('mongoose');

const userTasksSchema = new mongoose.Schema({
    tasktitle: String,
    taskuser: String,
    description: String,
    iscompleted: Boolean,
});

const UserTaskModel = mongoose.model('UserTask',userTasksSchema);

module.exports = UserTaskModel;