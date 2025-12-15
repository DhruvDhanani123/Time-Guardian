import React, { useState } from 'react';
import { Button, Modal, ModalHeader, ModalBody, ModalFooter } from 'reactstrap';
import axios from "axios";
import { Form } from 'react-bootstrap';
import { toast } from "react-toastify";
import taskStyle from './Task.module.css';

const CreateTaskPopup = ({ modal, toggle, save, refresh, setRefresh }) => {
    const [taskName, setTaskName] = useState('');
    const [assignedTo, setassignedTo] = useState('');
    const [description, setDescription] = useState('');
    const [users, setUsers] = useState([]);

    const capitalize = (str) => {
        return str.charAt(0).toUpperCase() + str.slice(1);
    };

    const handleChange = (e) => {
        const { name, value } = e.target;

        switch (name) {
            case "taskName":
                setTaskName(capitalize(value));
                break;
            case "assignedTo":
                setassignedTo(capitalize(value));
                break;
            case "description":
                setDescription(capitalize(value));
                break;
            default:
                break;
        }
    };

    const handleSelectUser = (e) => {
        axios.get('http://localhost:5000/emplist')
            .then(res => {
                if (res.status === 200) {
                    setUsers(res.data)
                    users.map(user => {
                        let fName = user["fName"]
                        console.log(fName);
                        //    return <option>{fName}</option>
                    })

                }
            })
            .catch(err => {
                console.error(err);
            })
    }

    const handleSave = (e) => {
        e.preventDefault()
        let taskObj = {}
        taskObj["Name"] = taskName
        taskObj["AssignedTo"] = assignedTo
        taskObj["Description"] = description
        save(taskObj)
        axios.post('http://localhost:5000/addtask', { title: taskName, user: assignedTo, description: description }, { headers: { 'Content-Type': 'application/json' } })
            .then(res => {
                if (res.status === 200) {
                    toast.success('Task Added successfully!');
                    setDescription("");
                    setTaskName("");
                    setassignedTo("");
                    setRefresh(!refresh)
                }
            })
            .catch(err => {
                console.error(err);
            })
    }

    return (
        <Modal isOpen={modal} toggle={toggle}>
            <ModalHeader toggle={toggle} style={{ color: 'var(--dark)' }}>Create Task</ModalHeader>
            <ModalBody>

                <div className="form-group">
                    <label className={taskStyle.label}>Task Name</label>
                    <input type="text" className={`form-control ${taskStyle.type} `} value={taskName} onChange={handleChange} name="taskName" />
                </div>
                {/* <div className="form-group">
                    <label className={taskStyle.label}>Assign to</label>
                    <input type="text" className={`form-control ${taskStyle.type} `} value={assignedTo} onChange={handleChange} name="assignedTo" />
                </div> */}
                <div className="form-group">
                    <label>Assign to</label>
                    <Form.Select aria-label="form-select" value={assignedTo} onChange={handleChange} onFocus={handleSelectUser} name="assignedTo">
                        <option value="">Select User</option>
                        {users.map((option, index) => (
                            <option value={option["fName"]} key={index}>{option["fName"]}</option>
                        ))}
                    </Form.Select>
                </div>
                <div className="form-group">
                    <label className={taskStyle.label}>Description</label>
                    <textarea rows="5" className={`form-control ${taskStyle.type} `} value={description} onChange={handleChange} name="description"></textarea>
                </div>

            </ModalBody>
            <ModalFooter>
                <Button color="primary" onClick={handleSave}>Create</Button>{' '}
                <Button color="warning" onClick={toggle}>Cancel</Button>
            </ModalFooter>
        </Modal>
    );
};

export default CreateTaskPopup;