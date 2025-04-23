const mongoose =require('mongoose');

const TasksSchema = new mongoose.Schema({
    tasktitle: String,
    taskuser: String,
    description: String,
    iscompleted: Boolean,
});

const TaskModel = mongoose.model('Task',TasksSchema);

module.exports = TaskModel;