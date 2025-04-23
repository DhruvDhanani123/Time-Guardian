const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
require('./Configuration');

const app = express();
app.use(bodyParser.json());
app.use(cors({ origin: ['http://localhost:3000'], methods: ['GET', 'POST', 'PUT', 'DELETE'], credentials: true }));
app.use(cookieParser());

const RegisterUserModel = require('./models/RegisterUser');
const PersonalInfoModel = require('./models/PersonalInfo');
const AttendanceModel = require('./models/Attendance');
const EmployeeInfoModel = require('./models/Employee');
const TaskModel = require('./models/Task');
const EarnedLeaveEmployeeModel = require('./models/EarnedLeaveRequest');
const LeaveEmployeeModel = require('./models/LeaveRequests');
const UserTaskModel = require('./models/UserTask');

//------------------------------------------------------------------------------------------------------------

app.post('/register', async (req, res) => {
    try {
        const { username, email, password, mono } = req.body;

        // Check if a user with the provided email already exists
        const existingUser = await RegisterUserModel.findOne({ email });

        if (existingUser) {
            console.log("User with this email already exists");
            return res.status(400).json({ error: 'User with this email already exists' });
        }

        // Hash the password
        const hash = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = await RegisterUserModel.create({
            username,
            email,
            password: hash,
            mono,
            is_admin: 0
        });

        console.log("Registration successful");
        res.json(newUser);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        // Find user by email
        const user = await RegisterUserModel.findOne({ email });

        if (user) {
            // Compare passwords
            const response = await bcrypt.compare(password, user.password);

            if (response) {
                // Generate JWT token
                const token = jwt.sign({ email: user.email, is_admin: user.is_admin }, "jwt-secret-key", { expiresIn: '1d' });
                res.cookie('token', token);

                if (user.is_admin === 1) {
                    return res.status(200).json({ message: "success !!", token, dashboard: "adminDashboard" });
                } else {
                    return res.status(200).json({ message: "success !!", token, dashboard: "userDashboard" });
                }


            } else {
                return res.status(401).json({ message: "Invalid user or password !!" });
            }
        } else {
            return res.status(404).json({ message: "Invalid user or password !!" });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error !!" });
    }
});

app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        // Find user by email
        const user = await RegisterUserModel.findOne({ email: email });

        if (!user) {
            return res.send({ Status: "User not existed" });
        }

        const token = jwt.sign({ id: user._id }, "jwt_secret_key", { expiresIn: "1d" });

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.email,
                pass: process.env.password// Add your Gmail password here
            }
        });

        const mailOptions = {
            from: process.env.email,
            to: email,
            subject: 'Reset Password Link',
            text: `http://localhost:3000/reset_password/${user._id}/${token}`
        };

        await transporter.sendMail(mailOptions);

        console.log(email);
        return res.send({ Status: "Success" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error !!" });
    }
});

app.post('/reset-password/:id/:token', async (req, res) => {
    // try {
    //     const { id, token } = req.params;
    //     const { password } = req.body;

    //     jwt.verify(token, "jwt_secret_key")
    //         .then(decoded => {
    //             // Decode successful
    //             return bcrypt.hash(password, 10);
    //         })
    //         .then(hash => {
    //             return RegisterUserModel.findByIdAndUpdate({ _id: id }, { password: hash });
    //         })
    //         .then(() => {
    //             return res.status(200).json({ Status: "Success" });
    //         })
    //         .catch(err => {
    //             return res.status(404).json({ message: err.message });
    //         });
    // } catch (error) {
    //     console.error(error);
    //     return res.status(404).json({ message: "Error with token !!" });
    // }
    try {
        const { id, token } = req.params;
        const { password } = req.body;

        // Verify token
        const decoded = jwt.verify(token, "jwt_secret_key");

        // Hash the password
        const hash = await bcrypt.hash(password, 10);

        // Update password in the database
        await RegisterUserModel.findByIdAndUpdate({ _id: id }, { password: hash });

        return res.status(200).json({ Status: "Success" });
    } catch (error) {
        console.error(error);
        return res.status(404).json({ message: "Error with token !!" });
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token'); // Clear the token cookie
    res.status(200).json({ message: "Logout successful" });
});
//------------------------------------------------------------------------------------------------------------

app.get('/personal', async (req, res) => {
    try {
        const { username } = req.query;
        const data = await PersonalInfoModel.find({ username });
        res.json(data);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/personalCreate', async (req, res) => {
    const existingUser = await PersonalInfoModel.findOne({ username: req.body.username });

    if (existingUser) {
        return res.status(400).send({ error: 'Your data is already registered !!' });
    }

    const personalInfo = new PersonalInfoModel({
        username: req.body.username,
        fName: req.body.fName,
        bDate: req.body.bDate,
        mono: req.body.mono,
        address: req.body.address,
        city: req.body.city,
        state: req.body.state
    });

    try {
        await personalInfo.save();
        res.status(201).send(personalInfo);
    } catch (error) {
        res.status(400).send(error);
    }
});

app.get('/getUser/:id', async (req, res) => {
    const id = req.params.id;
    try {
        const personalInfo = await PersonalInfoModel.findById({ _id: id });

        if (!personalInfo) {
            return res.status(404).send({ message: 'Personal information not found' });
        }
        res.send(personalInfo);
    } catch (error) {
        res.status(400).send(error);
    }
});

app.put('/personalEdit/:id', async (req, res) => {
    const id = req.params.id;
    try {
        const personalInfo = await PersonalInfoModel.findByIdAndUpdate({ _id: id }, req.body, {
            new: true, // Return the updated document
        });
        if (!personalInfo) {
            return res.status(404).send({ message: 'Personal information not found' });
        }
        res.send(personalInfo);
    } catch (error) {
        res.status(400).send(error);
    }
});

//------------------------------------------------------------------------------------------------------------

let startTime;

app.post('/start', (req, res) => {
    console.log('Received start request');
    startTime = new Date();
    res.sendStatus(200);
});

app.post('/stop', async (req, res) => {
    try {
        const username = req.body.username;
        const stopTime = new Date();
        const durationInMilliseconds = stopTime - startTime;
        const durationInMinutes = (durationInMilliseconds / (1000 * 60)).toPrecision(2);
        const today = new Date().toISOString().split('T')[0];

        // Check if a record already exists for the same day and username
        const existingRecord = await AttendanceModel.findOne({
            username: username,
            day: today
        });

        if (existingRecord) {
            // If record exists, update the duration
            existingRecord.duration = durationInMinutes;
            await existingRecord.save();
            console.log('Record updated successfully');
            res.json({ duration: durationInMinutes });
        } else {
            // If record doesn't exist, create a new entry
            const newAttendance = new AttendanceModel({
                username: username,
                day: today,
                duration: durationInMinutes
            });

            const savedAttendance = await newAttendance.save();
            console.log('Record inserted successfully');
            res.json({ duration: durationInMinutes });
        }
    } catch (error) {
        console.error('Error inserting/updating database:', error);
        res.status(500).send(error.message);
    }
});

app.get('/chartdata', async (req, res) => {
    try {
        const { username } = req.query;
        const data = await AttendanceModel.find({ username });
        res.json(data);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
})

//------------------------------------------------------------------------------------------------------------

app.get('/employee', async (req, res) => {
    try {
        const data = await EmployeeInfoModel.find({});
        res.json(data);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/employeeCreate', async (req, res) => {
    console.log("data  " + req.body);
    const existingUser = await EmployeeInfoModel.findOne({ email: req.body.email });

    if (existingUser) {
        return res.status(400).send({ error: 'This data is already Inserted !!' });
    }

    const employeeInfo = new EmployeeInfoModel(
        {
            fName: req.body.fName,
            email: req.body.email,
            mono: req.body.mono,
            joinDate: req.body.joinDate,
            salary: req.body.salary
        });

    try {
        await employeeInfo.save();
        res.status(201).send(employeeInfo);
    } catch (error) {
        console.log(error);
        res.status(400).send(error);
    }
});

app.get('/getemployee/:id', async (req, res) => {
    const id = req.params.id;
    try {
        const employeeInfo = await EmployeeInfoModel.findById({ _id: id });

        if (!employeeInfo) {
            return res.status(404).send({ message: 'Personal information not found' });
        }
        res.send(employeeInfo);
    } catch (error) {
        res.status(400).send(error);
    }
});

app.put('/employeeEdit/:id', async (req, res) => {
    const id = req.params.id;
    try {
        const employeeInfo = await EmployeeInfoModel.findByIdAndUpdate({ _id: id }, req.body, {
            new: true, // Return the updated document
        });
        if (!employeeInfo) {
            return res.status(404).send({ message: 'Personal information not found' });
        }
        res.send(employeeInfo);
    } catch (error) {
        res.status(400).send(error);
    }
});

app.delete('/delete-employee/:id', (req, res) => {
    const id = req.params.id;
    EmployeeInfoModel.findByIdAndDelete({ _id: id })
        .then(deletedEmployee => {
            if (!deletedEmployee) {
                return res.status(404).send({ message: 'Employee not found' });
            }
            res.json(deletedEmployee);
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({ message: 'Internal Server Error' });
        })
});

//------------------------------------------------------------------------------------------------------------

// -------Task Module Requests-------

app.post('/addtask', async (req, res) => {
    const { title, user, description } = req.body;

    UserTaskModel.create({ tasktitle: title, taskuser: user, description: description, iscompleted: false }).then(
        newTask => {
            console.log("Task added successfully to UserTask");
        }).catch(err => {
            console.error(err);
            res.status(500).json({ error: err.message });
        });

    TaskModel.create({ tasktitle: title, taskuser: user, description: description, iscompleted: false }).then(
        newTask => {
            console.log("Task added successfully");
            res.json(newTask);
        }).catch(err => {
            console.error(err);
            res.status(500).json({ error: err.message });
        });

});

app.post('/updatetask', async (req, res) => {
    const { title, user, description } = req.body;

    const filter = { tasktitle: title };
    const update = { taskuser: user, description: description, iscompleted: false };

    TaskModel.findOneAndUpdate(filter, update, { new: true }).then(
        newTask => {
            console.log("Task updated successfully");
            res.json(newTask);
        }).catch(err => {
            console.error(err);
            res.status(500).json({ error: err.message });
        });
});

app.post('/deletetask', async (req, res) => {
    const { title, user, description } = req.body;

    const filter = { tasktitle: title };
    const userfilter = { tasktitle: title, taskuser: user };

    UserTaskModel.findOneAndDelete(userfilter
    ).then(
        newTask => {
            console.log("Task deleted successfully from UserTask");
            // res.json(newTask);
        }).catch(err => {
            console.error(err);
            res.status(500).json({ error: err.message });
        });

    TaskModel.findOneAndDelete(filter
    ).then(
        newTask => {
            console.log("Task deleted successfully");
            res.json(newTask);
        }).catch(err => {
            console.error(err);
            res.status(500).json({ error: err.message });
        });
});

app.post('/completetask', async (req, res) => {
    const { title } = req.body;

    const filter = { tasktitle: title };
    const update = { iscompleted: true };

    TaskModel.findOneAndUpdate(filter, update, { new: true })
        .then(
            newTask => {
                console.log("Task completed successfully");
                // res.json(newTask.iscompleted);
            }
        )
        .catch(err => {
            console.error(err);
            res.status(500).json({ error: err.message });
        });
    UserTaskModel.findOneAndDelete(filter).then(
        deleteTask => {
            console.log("Task deleted successfully from Usertask");
            res.json(deleteTask);
        }).catch(err => {
            console.error(err);
            res.status(500).json({ error: err.message });
        });
});

// app.post('/gettasks', async (req, res) => {
//     const { username } = req.body;
//     // console.log("Email received: " + username);
//     try {
//         EmployeeInfoModel.findOne({ email: username }, 'fName').then(
//             getname => {
//                 console.log("Name found successfully: " + getname.fName);
//                 UserTaskModel.find({ taskuser: getname.fName }, 'tasktitle description').then(
//                     newData => {
//                         // console.log("Data found successfully: " + newData);
//                         res.json(newData);
//                     }
//                 ).catch(err => {
//                     console.error(err);
//                     res.status(500).json({ error: err.message });
//                 });
//             }

//         )
//         // res.json({ success: true, message: 'User deleted and added to other collection' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ success: false, error: 'Error moving user to other collection', detailedError: err });
//     }
// });

app.post('/gettasks', async (req, res) => {
    const { username } = req.body;
    try {
        const getname = await EmployeeInfoModel.findOne({ email: username }, 'fName');

        if (!getname) {
            return res.status(404).json({ error: "User not found" });
        }

        console.log("Name found successfully: " + getname.fName);

        const newData = await UserTaskModel.find({ taskuser: getname.fName }, 'tasktitle description');

        res.json(newData);

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Error retrieving tasks', detailedError: err.message });
    }
});


app.get('/getalltasks', async (req, res) => {
    TaskModel.find({}, 'tasktitle taskuser description iscompleted').then(
        newData => {
            // console.log("Data found successfully: " + newData);
            res.json(newData);
        }
    ).catch(err => {
        console.error(err);
        res.status(500).json({ error: err.message });
    });
})

app.get('/emplist', (req, res) => {
    EmployeeInfoModel.find()
        .then(users => res.json(users))
        .catch(err => res.json(err))
});

// -------------------------------------------------------------------------------------------------------------------

app.get('/getUsers', (req, res) => {
    EarnedLeaveEmployeeModel.find()
        .then(users => res.json(users))
        .catch(err => res.json(err))

});


app.get('/getUsers1', (req, res) => {
    LeaveEmployeeModel.find()
        .then(users => res.json(users))
        .catch(err => res.json(err))

});

app.delete('/deleteUser/:id', async (req, res) => {
    const userId = req.params.id;

    try {
        const deletedUser = await LeaveEmployeeModel.findOneAndDelete({ _id: userId });

        if (!deletedUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const transformedData = {
            emp_name: deletedUser.emp_name,
            email: deletedUser.email,
            status: 'Approved'
        };

        const TargetModel = require('./models/EarnedLeaveRequest');
        const newDocument = new TargetModel(transformedData);

        await newDocument.save();



        res.json({ success: true, message: 'User deleted and added to other collection' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Error moving user to other collection', detailedError: err });
    }
});

//---------------------------------------------------------------------------------------------------------------------

app.post('/sendLeaveRequest', async (req, res) => {
    try {
        const { emp_name, email } = req.body;

        console.log('Received email:', email);
        const newDocument = new LeaveEmployeeModel({
            emp_name,
            email
        });

        await newDocument.save();

        res.json({ success: true, message: 'Data sent to other collection' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Error sending data to other collection', detailedError: err });
    }
});

app.post('/checkRequest', async (req, res) => {
    const { email } = req.body;

    // console.log('Received email:', email);
    const filter = { email: email };

    EarnedLeaveEmployeeModel.findOne(filter, 'status').then(
        newData => {
            // console.log("Data found successfully: " + newData);
            if (newData.status === 'Approved') {
                return res.json('Your Leave Request has been Approved !!');
            }
            return res.json('Your Leave Request is Pending !!');
        }
    ).catch(err => {
        console.error(err.message);
        return res.status(500).json({ error: err.message });
    });
});

// -------------------------------------------------------------------------------------------------------------------

app.listen(5000, () => {
    console.log('Server is running on http://localhost:5000');
});
