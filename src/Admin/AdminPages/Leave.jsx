import React, { useState, useEffect } from 'react';
import leave from './Leave.module.css';
import { Form } from 'react-bootstrap';
// import { NavLink, useNavigate } from 'react-router-dom';
// import { VscEye, VscEyeClosed } from 'react-icons/vsc';
import axios from 'axios';
// import { toast } from 'react-toastify';
import EarnedLeaveData from './EarnedLeaveData';


const Leave = () => {
    const [refresh, setRefresh] = useState(false);

    const myStyle = {
        backgroundColor: '#4E31AA',
        color: 'white',
        fontSize: '15px',
        justifyContent: 'center',

    }
    

    const [users1, setUsers1] = useState([]);

    useEffect(() => {
        axios.get('http://localhost:5000/getUsers1')
            .then(users =>
                setUsers1(users.data)
            )
            .catch(error => {
                console.error(error);
            })
    }, [refresh]);

    const handleDelete = (userId) => {
        axios.delete(`http://localhost:5000/deleteUser/${userId}`)
            .then(response => {
                setRefresh(!refresh);
                if (response.data.success) {
                    setUsers1(users1.filter(user => user._id !== userId));
                } else {
                    console.error('Error deleting user');
                }
                // handleReloadPage();
            })
            .catch(error => {
                console.error(error);
            });

           
    };
    
    

    // const handleReloadPage = () => {
    //     window.location.reload();
    // };

    return (
        <>
            <div className={leave.pacont}>
                <div className={`container mx-auto`} id={leave.cont}>

                    <div className='row d-flex align-items-center' >

                        <div className='col-lg-4 col-lg-10 mx-auto '>
                            <Form className={leave.frm}>
                                <p style={{ fontSize: "30px", fontWeight: "900", color: "var(--dark)" }} className='font-weight-bold'>Employees At Leave</p>
                                <div className='d-flex gap-5 ' id={leave.roww}>


                                    <div className={`container border ${leave.cont} mx-auto`} style={{ boxShadow: '1px 1px 20px var(--hover)', borderRadius: '10px' }}>

                                        <div className='row d-flex align-items-center' >

                                            <div className='col-lg-4 col-lg-10 mx-auto '>
                                                <Form className={leave.frm}>

                                                    <p style={{ fontSize: "30px", fontWeight: "900", color: "var(--dark)" }} className='font-weight-bold'>Earned Requests</p>

                                                    <EarnedLeaveData />
                                                </Form>

                                            </div>
                                        </div>
                                    </div>

                                    <div className={`container border ${leave.cont} mx-auto`} style={{ boxShadow: '1px 1px 20px var(--hover)', borderRadius: '10px' }}>

                                        <div className='row d-flex align-items-center' >

                                            <div className='col-lg-4 col-lg-10 mx-auto '>
                                                <Form className={leave.frm} >

                                                    <p style={{ fontSize: "30px", fontWeight: "900", color: "var(--dark)" }} className='font-weight-bold'>Pending Requests</p>

                                                    <div className='overflow-x-auto'>
                                                        <table className='table table-hover text-center table-bordered table-responsive' >
                                                            <thead style={{ color: 'var(--darker)' }}>
                                                                <th>
                                                                    UserName
                                                                </th>
                                                                <th>
                                                                    Email Id
                                                                </th>
                                                                <th>
                                                                    Approval
                                                                </th>
                                                            </thead>

                                                            <tbody>
                                                                {users1.map(user => (
                                                                    <tr key={user._id}>
                                                                        <td>
                                                                            {user.emp_name}
                                                                        </td>
                                                                        <td>
                                                                            {user.email}
                                                                        </td>
                                                                        <td>
                                                                            <button className={`btn btn-sm`} style={myStyle} type="button" onClick={() => handleDelete(user._id)}>
                                                                                Confirm
                                                                            </button>
                                                                        </td>

                                                                    </tr>
                                                                ))}
                                                            </tbody>


                                                        </table>
                                                    </div>
                                                </Form>

                                            </div>
                                        </div>
                                    </div>


                                </div>
                            </Form>

                        </div>
                        <div className={`container  ${leave.cont} mx-auto`} style={{ marginTop: '3rem' }}>

                            <div className='row d-flex align-items-center' >

                                <div className='col-lg-4 col-lg-10 mx-auto d-flex justify-content-center'>
                                    <button className={`btn btn-sm`} style={myStyle} type="button" onClick={()=> {setRefresh(!refresh)}}>
                                        Refresh
                                    </button>
                                </div>
                            </div>

                        </div>
                    </div>
                </div>
            </div>
        </>
    )
}

export default Leave;
