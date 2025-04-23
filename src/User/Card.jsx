import React, { useState } from 'react';
// import EditTask from './EditTask';
import cardStyle from './Card.module.css';
// import 'font-awesome/css/font-awesome.min.css';
// import { FaEdit, FaTrashAlt } from 'react-icons/fa';
import axios from "axios";
import { toast } from "react-toastify";
import { Form } from 'react-bootstrap';

const Card = ({ taskObj, index, deleteTask, updateListArray }) => {
    const [modal, setModal] = useState(false);
    const { tasktitle, taskuser, description } = taskObj;
    const colors = [
        {
            primaryColor: "#5D93E1",
            secondaryColor: "#ECF3FC"
        },
        {
            primaryColor: "#F9D288",
            secondaryColor: "#FEFAF1"
        },
        {
            primaryColor: "#5DC250",
            secondaryColor: "#F2FAF1"
        },
        {
            primaryColor: "#F48687",
            secondaryColor: "#FDF1F1"
        },
        {
            primaryColor: "#B964F7",
            secondaryColor: "#F3F0FD"
        }
    ]

    const toggle = () => {
        setModal(!modal);
    }

    const updateTask = (obj) => {
        updateListArray(obj, index)
    }

    const handleComplete = () => {
        axios.post('http://localhost:5000/completetask', { title: tasktitle }, { headers: { 'Content-Type': 'application/json' } })
            .then(res => {
                if (res.status === 200) {
                    toast.success('Task completed successfully!');
                }
            })
            .catch(err => {
                console.error(err);
            })
        setTimeout(() => {
        deleteTask(index)
        }, 3000);
    }
    
    return (

        <>
            <div className={`w-100 m-2 ${cardStyle.card_wrapper}`}>
                <div className={cardStyle.card_top} style={{ backgroundColor: colors[index % 5].primaryColor }}>
                </div>

                <div className={`d-flex flex-column ${cardStyle.task_holder}`}>
                    <span className={cardStyle.card_header} style={{ backgroundColor: colors[index % 5].secondaryColor, borderRadius: "10px" }}>{tasktitle}
                    </span>
                    {/* <span>
                        Assigned To: <span className={cardStyle.card_header} style={{ backgroundColor: colors[index % 5].secondaryColor, borderRadius: "10px" }}>{taskObj.AssignedTo}
                        </span>
                    </span> */}
                    <p className={`mt-3 ${cardStyle.card_description}`}>{description}</p>

                    <div style={{ fontSize: '20px', bottom: '20px', position: 'sticky' }} className='d-flex justify-content-end'>
                        {/* <i style={{ color: colors[index % 5].primaryColor, cursor: "pointer", marginRight: '5px' }} onClick={() => setModal(true)}><FaEdit /></i> */}
                        <i style={{ color: colors[index % 5].primaryColor, cursor: "pointer" }}>
                            {/* <FaTrashAlt /> */}
                            <Form.Check type="checkbox" label="Mark as Complete" onClick={handleComplete}/>
                            </i>
                    </div>

                </div>
                {/* <EditTask modal={modal} toggle={toggle} updateTask={updateTask} taskObj={taskObj} /> */}

            </div>
        </>

    );
};

export default Card;