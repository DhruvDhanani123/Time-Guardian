import React, { useEffect, useState } from 'react';
import axios from 'axios';
import CreateTask from './CreateTask'
import Card from './Card';
import cardStyle from './Card.module.css';
import { FaRedo } from 'react-icons/fa';

const TaskList = () => {
    const [modal, setModal] = useState(false);
    const [taskList, setTaskList] = useState([]);
    const [refresh, setRefresh] = useState(false);

    useEffect(() => {
        let tempObj = {}

        axios.get('http://localhost:5000/getalltasks').then(response => {
            setTaskList(response.data);
        }).catch(error => console.error('Error:', error));

    }, [refresh])


    const deleteTask = (index) => {
        let tempList = taskList
        tempList.splice(index, 1)
        localStorage.setItem("taskList", JSON.stringify(tempList))
        setTaskList(tempList)
        // setRefresh(!refresh)
        // window.location.reload()
    }

    const updateListArray = (obj, index) => {
        let tempList = taskList
        tempList[index] = obj
        localStorage.setItem("taskList", JSON.stringify(tempList))
        setTaskList(tempList)
        setRefresh(!refresh)
        //window.location.reload()
    }

    const toggle = () => {
        setModal(!modal);
    }

    const saveTask = (taskObj) => {
        let tempList = taskList
        tempList.push(taskObj)
        localStorage.setItem("taskList", JSON.stringify(tempList))
        setTaskList(taskList)
        setModal(false)
    }


    return (
        <>
            {/* <div className = {`text-center ${cardStyle.header}`}>
                <h3>Assign Tasks to Employees</h3>
                <button className = "btn btn-primary mt-2" onClick = {() => setModal(true)} >Assign Task</button>
            </div>
            <div className ={`${cardStyle.task_container}`}>
            {taskList && taskList.map((obj , index) => <Card taskObj = {obj} index = {index} deleteTask = {deleteTask} updateListArray = {updateListArray}/> )}
            </div>
            <CreateTask toggle = {toggle} modal = {modal} save = {saveTask}/> */}

            <div className='container pt-1 pb-1'>
                <div className={`text-center p-md-3 p-1 ${cardStyle.header}`}>
                    <h3>Assign Tasks to Employees</h3>
                    <div className={`d-flex`}>

                        <button className={`btn p-1 ${cardStyle.btn}`} onClick={() => setModal(true)} >Assign Task</button>
                    </div>
                </div>

                <div className={`${cardStyle.task_container}`}>
                    <button className={`btn m-2 p-1 ${cardStyle.btn}`} onClick={() => { setRefresh(!refresh) }} ><FaRedo /></button>
                    {taskList && taskList.map((obj, index) => <Card taskObj={obj} index={index} key={index} deleteTask={deleteTask} updateListArray={updateListArray} refresh={refresh} setRefresh={setRefresh}/>)}
                </div>

                <CreateTask toggle={toggle} modal={modal} save={saveTask} refresh={refresh} setRefresh={setRefresh}/>
            </div>
        </>
    );
};

export default TaskList;