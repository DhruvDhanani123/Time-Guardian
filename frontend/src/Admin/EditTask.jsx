import React, { useState , useEffect} from 'react';
import { Button, Modal, ModalHeader, ModalBody, ModalFooter } from 'reactstrap';
import axios from "axios";
import taskStyle from  './Task.module.css';
import { toast } from "react-toastify";

const EditTaskPopup = ({modal, toggle, updateTask, taskObj, refresh, setRefresh}) => {
    const [taskName, setTaskName] = useState('');
    const [assignedTo, setassignedTo] = useState('');
    const [description, setDescription] = useState('');

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

    useEffect(() => {
        setTaskName(taskObj.Name)
        setassignedTo(taskObj.AssignedTo)
        setDescription(taskObj.Description)
    },[])

    const handleUpdate = (e) => {
        e.preventDefault();
        let tempObj = {}
        tempObj['Name'] = taskName
        tempObj["AssignedTo"] = assignedTo
        tempObj['Description'] = description
        updateTask(tempObj)
        axios.post('http://localhost:5000/updatetask', {title: taskName, user: assignedTo, description: description}, {headers: {'Content-Type': 'application/json'}})
        .then(res => {
            if(res.status === 200){
                toast.success('Task Added successfully!');
                setRefresh(!refresh)
            }
        })
        .catch(err => {
            console.error(err);
        })
    }

    return (
        <Modal isOpen={modal} toggle={toggle}>
            <ModalHeader toggle={toggle}  style={{color:'var(--dark)'}}>Update Task</ModalHeader>
            <ModalBody>
            
                    <div className = "form-group">
                        <label className={taskStyle.label} >Task Name</label>
                        <input type="text" className={`form-control ${taskStyle.type}`}  value = {taskName} onChange = {handleChange} name = "taskName"/>
                    </div>
                    <div className = "form-group">
                        <label className={taskStyle.label} >Assign to</label>
                        <input type="text" className={`form-control ${taskStyle.type}`}  value = {assignedTo} onChange = {handleChange} name = "assignedTo"/>
                    </div>
                    <div className = "form-group">
                        <label className={taskStyle.label} >Description</label>
                        <textarea rows = "5" className={`form-control ${taskStyle.type}`}  value = {description} onChange = {handleChange} name = "description"></textarea>
                    </div>
                
            </ModalBody>
            <ModalFooter>
            <Button color="primary" onClick={handleUpdate}>Update</Button>{' '}
            <Button color="warning" onClick={toggle}>Cancel</Button>
            </ModalFooter>
      </Modal>
    );
};

export default EditTaskPopup;