import axios from 'axios';
import React, { useState, useEffect } from 'react';
import style from './EarnedLeaveData.module.css'

const LeaveDisplayData = () => {
    const [users1, setUsers1] = useState([]);

    useEffect(() => {
        axios.get('http://localhost:5000/getUsers1')
            .then(users =>
                setUsers1(users.data)
            )
            .catch(error => {
                console.error(error);
            })
    }, []);

    const myStyle = {
        backgroundColor: '#4E31AA',
        color: 'white',
        fontSize: '15px',

    }

    const handleDelete = (userId) => {
        axios.delete(`http://localhost:5000/deleteUser/${userId}`)
            .then(response => {
                if (response.data.success) {
                    setUsers1(users1.filter(user => user._id !== userId));
                } else {
                    console.error('Error deleting user');
                }
            })
            .catch(error => {
                console.error(error);
            });
    };

    return (
        <>
        <div className='overflow-x-auto'>
            <table className='table table-hover text-center table-bordered table-responsive' >
                <thead style={{color:'var(--darker)'}}>                    
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
        </>
    );
}

export default LeaveDisplayData;
