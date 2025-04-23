import axios from 'axios';
import React, { useEffect, useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom';
import { FaEdit, FaTrashAlt, FaUserPlus } from 'react-icons/fa';
import TaskList from '../TaskList';
import employeeStyle from './Employee.module.css';
import Swal from 'sweetalert2';
import { toast } from 'react-toastify';

const Employee = () => {
    const [users, setUsers] = useState([{}]);
    const [username, setUsername] = useState(localStorage.getItem('username'));
    const [loggedIn, setloggedIn] = useState(localStorage.getItem('loggedIn'));
    const [greeting, setGreeting] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        axios.get(`http://localhost:5000/employee`)
            .then(response => {
                setUsers(response.data);
            })
            .catch(error => {
                console.error(error);
            });
    }, []);

    const handleDelete = (id) => {
        axios.delete(`http://localhost:5000/delete-employee/${id}`)

            .then(res => {
                console.log(res);
                window.location.reload();

            })
            .catch(err => {
                console.log(err);
            })
    }


    // const handleDelete = (id) => {
    //     Swal.fire({
    //         title: 'Are you sure?',
    //         text: "You won't be able to revert this!",
    //         icon: 'warning',
    //         showCancelButton: true,
    //         confirmButtonColor: '#3085d6',
    //         cancelButtonColor: '#d33',
    //         confirmButtonText: 'Yes, delete it!'
    //     }).then((result) => {
    //         if (result.isConfirmed) {
    //             axios.delete(`http://localhost:5000/delete-employee/${id}`)
    //                 .then(res => {
    //                     console.log(res);
    //                     Swal.fire(
    //                         'Deleted!',
    //                         'Your file has been deleted.',
    //                         'success'
    //                     ).then(() => {
    //                         window.location.reload();
    //                         // navigate('/employee')
    //                     });
    //                 })
    //                 .catch(err => {
    //                     console.log(err);
    //                 })
    //         }
    //     });
    // }
    useEffect(() => {
        setUsername(localStorage.getItem('username'));
        const currentHour = new Date().getHours();

        if (currentHour >= 5 && currentHour < 12) {
            setGreeting('Good Morning');
        } else if (currentHour >= 12 && currentHour < 18) {
            setGreeting('Good Afternoon');
        } else if (currentHour >= 18 && currentHour < 23) {
            setGreeting('Good Afternoon');
        } else {
            setGreeting('Good Night');
        }

        if (loggedIn === 'false') {
            navigate('/login');
            console.log('You are not logged in');
        };
    }, []);

    return (
        <>
            <h1 style={{color:'var(--dark)'}}>{greeting}, {username}!</h1>
            <div className='container pt-1 pb-1 text-end'>
                <NavLink className={`mb-3 btn btn-success`} to={'/employee-create'}>
                    <FaUserPlus />
                </NavLink>

                {
                    <div className="overflow-x-auto">
                        <table className={`${employeeStyle.table} table-bordered text-center`}>
                            <thead className={employeeStyle.thead}>
                                <tr>
                                    <th scope="col" style={{ minWidth: '200px' }} className='position-sticky'>Full Name</th>
                                    <th scope="col" style={{ minWidth: '150px' }}>E-mail</th>
                                    <th scope="col" style={{ minWidth: '120px' }}>Date of Joining</th>
                                    <th scope="col" style={{ minWidth: '150px' }}>Mobile No</th>
                                    <th scope="col" style={{ minWidth: '100px' }}>Salary</th>
                                    <th scope="col" style={{ minWidth: '150px' }}>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {
                                    users?.map((user, i) => {
                                        return (
                                            <>
                                                <tr key={user._id} className={`${employeeStyle.trow}`}>
                                                    <td style={{ minWidth: '200px' }} className='position-sticky'>{user?.fName}</td>
                                                    <td style={{ minWidth: '150px' }}>{user?.email}</td>
                                                    <td style={{ minWidth: '120px' }}>{user?.joinDate}</td>
                                                    <td style={{ minWidth: '150px' }}>{user?.mono}</td>
                                                    <td style={{ minWidth: '100px' }}>{user?.salary}</td>
                                                    <td style={{ minWidth: '150px' }}>
                                                        <NavLink className='btn btn-warning m-2' to={`/employee-edit/${user._id}`}>
                                                            <FaEdit />
                                                        </NavLink>
                                                        <button className='btn btn-danger' onClick={(e) => handleDelete(user._id)} >
                                                            <FaTrashAlt />
                                                        </button>
                                                    </td>
                                                </tr>
                                            </>
                                        )
                                    })
                                }
                            </tbody>
                        </table>
                    </div>
                }

            </div>
        </>
    )
}

export default Employee;